from supabase import create_client, Client
import os
import logging
import hashlib
import streamlit as st
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("database.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._init_client()
        return cls._instance

    def _init_client(self):
        # Try to get from st.secrets first (for Streamlit Cloud), then fallback to os.getenv
        url = None
        key = None
        
        try:
            if "SUPABASE_URL" in st.secrets:
                url = st.secrets["SUPABASE_URL"]
            if "SUPABASE_KEY" in st.secrets:
                key = st.secrets["SUPABASE_KEY"]
        except:
            pass

        if not url: url = os.getenv("SUPABASE_URL")
        if not key: key = os.getenv("SUPABASE_KEY")
        
        if not url or not key:
            logger.error("SUPABASE_URL or SUPABASE_KEY not found in environment variables or secrets.")
            self.supabase = None
        else:
            try:
                self.supabase = create_client(url, key)
                logger.info("Supabase client initialized successfully.")
            except Exception as e:
                logger.error(f"Error initializing Supabase client: {e}")
                self.supabase = None
        
        # Compatibility with app.py's connection status check
        self._pool = self.supabase 

    def test_connection(self):
        if not self.supabase:
            return False
        try:
            # Simple query to test connection
            self.supabase.table("users").select("id").limit(1).execute()
            return True
        except Exception as e:
            logger.error(f"Test connection failed: {e}")
            return False

    def hash_password(self, password):
        """
        Menghasilkan hash SHA256 dari password.
        ⚠️ Menggunakan SHA256 (kalah aman dibanding bcrypt)
        """
        return hashlib.sha256(password.encode()).hexdigest()

    # AUTHENTICATION
    def authenticate_user(self, username, hashed_password):
        if not self.supabase: return None
        try:
            response = self.supabase.table("users") \
                .select("id, username") \
                .eq("username", username) \
                .eq("password", hashed_password) \
                .execute()
            
            if response.data:
                return response.data[0]
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
        
        return None

    def register_user(self, username, hashed_password):
        if not self.supabase: return None, "Supabase not connected"
        try:
            # Check if username exists
            existing = self.supabase.table("users") \
                .select("id") \
                .eq("username", username) \
                .execute()
            
            if existing.data:
                return None, "Username sudah digunakan"
            
            # Insert user
            response = self.supabase.table("users") \
                .insert({"username": username, "password": hashed_password}) \
                .execute()
            
            if response.data:
                user_id = response.data[0]['id']
                logger.info(f"User {username} registered with ID {user_id}")
                return user_id, "Registrasi berhasil"
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return None, f"Database error: {e}"
        
        return None, "Gagal terhubung ke database"

    def delete_user(self, user_id):
        if not self.supabase: return False
        try:
            self.supabase.table("users").delete().eq("id", user_id).execute()
            logger.info(f"User with ID {user_id} deleted")
            return True
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False

    def reset_database(self):
        if not self.supabase: return False
        try:
            # Note: We use neq("id", 0) as a hack to delete all rows since neq is required
            self.supabase.table("history").delete().neq("id", 0).execute()
            self.supabase.table("users").delete().neq("id", 0).execute()
            logger.info("Database reset: All users and history cleared.")
            return True
        except Exception as e:
            logger.error(f"Error resetting database: {e}")
            return False

    # HISTORY
    def save_history(self, url, result, final_score, user_id=None):
        if not self.supabase: return None
        
        # Admin check for ID 0
        db_user_id = user_id if user_id != 0 else None
        
        now = datetime.now()
        data = {
            "url": url,
            "result": result,
            "final_score": final_score,
            "user_id": db_user_id
        }

        try:
            response = self.supabase.table("history").insert(data).execute()
            if response.data:
                logger.info(f"History saved for URL: {url}")
                return {
                    "url": url,
                    "result": result,
                    "final_score": final_score,
                    "time": now.strftime("%d %b %Y, %H:%M")
                }
        except Exception as e:
            logger.error(f"Error saving history: {e}")
            
        return None

    def get_history(self, limit=100):
        if not self.supabase: return []
        try:
            response = self.supabase.table("history") \
                .select("*") \
                .order("time", desc=True) \
                .limit(limit) \
                .execute()
            return self._format_history(response.data)
        except Exception as e:
            logger.error(f"Error fetching history: {e}")
            return []

    def get_history_by_user(self, user_id, limit=100):
        if not self.supabase: return []
        try:
            query = self.supabase.table("history").select("*")
            
            if user_id != 0:
                query = query.eq("user_id", user_id)
            else:
                query = query.is_("user_id", "null")
            
            response = query.order("time", desc=True).limit(limit).execute()
            return self._format_history(response.data)
        except Exception as e:
            logger.error(f"Error fetching user history: {e}")
            return []

    def _format_history(self, rows):
        results = []
        for row in rows:
            row_dict = dict(row)
            if row_dict.get('time'):
                try:
                    # Supabase returns ISO strings like 2024-05-04T17:00:00+00:00
                    # We convert it to the format app.py expects
                    dt = datetime.fromisoformat(row_dict['time'].replace('Z', '+00:00'))
                    row_dict['time'] = dt.strftime("%d %b %Y, %H:%M")
                except Exception as e:
                    logger.warning(f"Error formatting time {row_dict['time']}: {e}")
            results.append(row_dict)
        return results

    def clear_history(self, user_id=None):
        if not self.supabase: return
        try:
            query = self.supabase.table("history").delete()
            if user_id is not None:
                if user_id != 0:
                    query = query.eq("user_id", user_id)
                else:
                    query = query.is_("user_id", "null")
            
            query.execute()
            logger.info(f"History cleared{' for user ' + str(user_id) if user_id else '.'}")
        except Exception as e:
            logger.error(f"Error clearing history: {e}")

# Global instance
db_manager = DatabaseManager()

def test_connection():
    return db_manager.test_connection()