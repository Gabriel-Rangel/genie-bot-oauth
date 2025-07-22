"""
Authentication module for Microsoft SSO integration with Databricks.
Handles OAuth flow with Microsoft Entra ID and Databricks OAuth.
"""

import os
import json
import streamlit as st
import requests
from typing import Dict, Optional
from urllib.parse import urlencode
import msal
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class AuthenticationManager:
    """Manages Microsoft SSO and Databricks OAuth authentication"""
    
    def __init__(self):
        self.azure_tenant_id = os.getenv("AZURE_TENANT_ID")
        self.azure_client_id = os.getenv("AZURE_CLIENT_ID")
        self.azure_client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.databricks_host = os.getenv("DATABRICKS_HOST")
        self.databricks_oauth_client_id = os.getenv("DATABRICKS_OAUTH_CLIENT_ID")
        self.databricks_oauth_client_secret = os.getenv("DATABRICKS_OAUTH_CLIENT_SECRET")
        self.redirect_uri = os.getenv("REDIRECT_URI", "http://localhost:8505")
        
        # Microsoft Graph and Databricks scopes
        self.microsoft_scopes = ["https://graph.microsoft.com/User.Read"]  # Use full Microsoft Graph scope
        self.databricks_scopes = ["all-apis"]  # Use all-apis scope to access Genie API
        
        # Initialize MSAL app
        if not all([self.azure_client_id, self.azure_client_secret, self.azure_tenant_id]):
            logger.error("Missing Azure configuration. Please check your .env file.")
            logger.debug(f"tenant_id: {'✓' if self.azure_tenant_id else '✗'}")
            logger.debug(f"client_id: {'✓' if self.azure_client_id else '✗'}")
            logger.debug(f"client_secret: {'✓' if self.azure_client_secret else '✗'}")
            self.msal_app = None
        else:
            self.msal_app = msal.ConfidentialClientApplication(
                client_id=self.azure_client_id,
                client_credential=self.azure_client_secret,
                authority=f"https://login.microsoftonline.com/{self.azure_tenant_id}"
            )
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated and has valid tokens"""
        # First, try to restore from file if session state is empty
        if not st.session_state.get("microsoft_token") or not st.session_state.get("databricks_token"):
            saved_tokens = self._load_tokens_from_file()
            if saved_tokens:
                if "microsoft_token" in saved_tokens and not st.session_state.get("microsoft_token"):
                    logger.debug("Restoring Microsoft token from file")
                    st.session_state["microsoft_token"] = saved_tokens["microsoft_token"]
                    st.session_state["microsoft_user_info"] = saved_tokens.get("microsoft_user_info", {})
                
                if "databricks_token" in saved_tokens and not st.session_state.get("databricks_token"):
                    logger.debug("Restoring Databricks token from file")
                    st.session_state["databricks_token"] = saved_tokens["databricks_token"]
        
        # Check for Microsoft token (try multiple storage methods)
        microsoft_token = (
            st.session_state.get("microsoft_token") or 
            st.session_state.get("auth_microsoft_token")
        )
        
        # Check for Databricks token
        databricks_token = st.session_state.get("databricks_token")
        
        # Debug logging
        logger.debug(f"Authentication check:")
        logger.debug(f"  Microsoft token present: {'✓' if microsoft_token else '✗'}")
        logger.debug(f"  Databricks token present: {'✓' if databricks_token else '✗'}")
        
        # If Microsoft token is missing but backup exists, restore it
        if not st.session_state.get("microsoft_token") and st.session_state.get("auth_microsoft_token"):
            logger.debug("Restoring Microsoft token from backup")
            st.session_state["microsoft_token"] = st.session_state["auth_microsoft_token"]
            st.session_state["microsoft_user_info"] = st.session_state.get("auth_microsoft_user", {})
            microsoft_token = st.session_state["microsoft_token"]
        
        if microsoft_token:
            logger.debug(f"  Microsoft token (first 20 chars): {microsoft_token[:20]}...")
        if databricks_token:
            logger.debug(f"  Databricks token (first 20 chars): {databricks_token[:20]}...")
        
        return (
            microsoft_token is not None and
            databricks_token is not None
        )
    
    def _restore_from_localstorage(self):
        """Try to restore tokens from browser localStorage"""
        try:
            # Create a hidden form to retrieve localStorage data
            st.components.v1.html("""
            <script>
                const microsoftToken = localStorage.getItem('microsoft_token');
                const microsoftUserInfo = localStorage.getItem('microsoft_user_info');
                
                if (microsoftToken) {
                    console.log('Found Microsoft token in localStorage');
                    // Send data back to Streamlit (this won't work directly, so we'll use a different approach)
                }
            </script>
            """, height=0)
        except Exception as e:
            logger.debug(f"Could not restore from localStorage: {e}")
            pass
    
    def _save_tokens_to_file(self, tokens: Dict):
        """Save tokens to a temporary file for persistence"""
        try:
            import tempfile
            temp_dir = tempfile.gettempdir()
            token_file = os.path.join(temp_dir, f"streamlit_auth_{os.getpid()}.json")
            
            with open(token_file, 'w') as f:
                json.dump(tokens, f)
            
            logger.debug(f"Tokens saved to file: {token_file}")
        except Exception as e:
            logger.error(f"Failed to save tokens to file: {e}")
    
    def _load_tokens_from_file(self) -> Optional[Dict]:
        """Load tokens from temporary file"""
        try:
            import tempfile
            temp_dir = tempfile.gettempdir()
            token_file = os.path.join(temp_dir, f"streamlit_auth_{os.getpid()}.json")
            
            if os.path.exists(token_file):
                with open(token_file, 'r') as f:
                    tokens = json.load(f)
                logger.debug(f"Tokens loaded from file: {token_file}")
                return tokens
            return None
        except Exception as e:
            logger.debug(f"Failed to load tokens from file: {e}")
            return None
    
    def get_microsoft_auth_url(self) -> str:
        """Generate Microsoft OAuth authorization URL"""
        if not self.msal_app:
            logger.error("MSAL app not initialized. Check Azure configuration.")
            return None
            
        try:
            auth_url = self.msal_app.get_authorization_request_url(
                scopes=self.microsoft_scopes,
                redirect_uri=self.redirect_uri,
                state="microsoft_auth"
            )
            logger.debug(f"Generated auth URL: {auth_url}")
            return auth_url
        except Exception as e:
            logger.error(f"Error generating Microsoft auth URL: {str(e)}")
            return None
    
    def handle_microsoft_callback(self, auth_code: str) -> Optional[Dict]:
        """Handle Microsoft OAuth callback and get user info"""
        try:
            logger.debug(f"Handling Microsoft callback with code: {auth_code[:10]}...")
            result = self.msal_app.acquire_token_by_authorization_code(
                code=auth_code,
                scopes=self.microsoft_scopes,
                redirect_uri=self.redirect_uri
            )
            
            if "access_token" in result:
                logger.debug("Microsoft token acquired successfully")
                # Get user info from Microsoft Graph
                user_info = self._get_microsoft_user_info(result["access_token"])
                
                # Store in session state with multiple methods
                st.session_state["microsoft_token"] = result["access_token"]
                st.session_state["microsoft_user_info"] = user_info
                st.session_state["auth_microsoft_token"] = result["access_token"]
                st.session_state["auth_microsoft_user"] = user_info
                
                # ALSO store in a temporary file for persistence across page reloads
                self._save_tokens_to_file({
                    "microsoft_token": result["access_token"],
                    "microsoft_user_info": user_info
                })
                
                logger.debug(f"Microsoft user info stored: {user_info.get('displayName', 'Unknown')}")
                
                # Verify storage immediately
                stored_token = st.session_state.get("microsoft_token")
                if stored_token:
                    logger.debug("Microsoft token verified in session state")
                else:
                    logger.error("Failed to store Microsoft token in session state!")
                
                return user_info
            else:
                logger.error(f"Microsoft OAuth error: {result.get('error_description')}")
                return None
                
        except Exception as e:
            logger.error(f"Error handling Microsoft callback: {str(e)}")
            return None
    
    def _get_microsoft_user_info(self, access_token: str) -> Dict:
        """Get user information from Microsoft Graph API"""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting Microsoft user info: {str(e)}")
            return {}
    
    def get_databricks_auth_url(self) -> str:
        """Generate Databricks OAuth authorization URL"""
        try:
            databricks_host_clean = self.databricks_host.replace("https://", "").replace("http://", "")
            
            params = {
                "response_type": "code",
                "client_id": self.databricks_oauth_client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(self.databricks_scopes),
                "state": "databricks_auth"
            }
            
            auth_url = f"https://{databricks_host_clean}/oidc/v1/authorize?" + urlencode(params)
            return auth_url
        except Exception as e:
            logger.error(f"Error generating Databricks auth URL: {str(e)}")
            return None
    
    def handle_databricks_callback(self, auth_code: str) -> Optional[str]:
        """Handle Databricks OAuth callback and get access token"""
        try:
            logger.debug(f"Handling Databricks callback with code: {auth_code[:10]}...")
            databricks_host_clean = self.databricks_host.replace("https://", "").replace("http://", "")
            token_url = f"https://{databricks_host_clean}/oidc/v1/token"
            
            data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.databricks_oauth_client_id,
                "client_secret": self.databricks_oauth_client_secret
            }
            
            logger.debug(f"Requesting token from: {token_url}")
            response = requests.post(
                token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            response.raise_for_status()
            
            token_response = response.json()
            access_token = token_response.get("access_token")
            
            if access_token:
                logger.debug("Databricks token acquired successfully")
                st.session_state.databricks_token = access_token
                st.session_state.databricks_token_type = token_response.get("token_type", "Bearer")
                
                # Also save to file for persistence
                existing_tokens = self._load_tokens_from_file() or {}
                existing_tokens["databricks_token"] = access_token
                self._save_tokens_to_file(existing_tokens)
                
                logger.debug(f"Databricks token stored (first 20 chars): {access_token[:20]}...")
                return access_token
            else:
                logger.error(f"No access token in Databricks response: {token_response}")
                return None
                
        except Exception as e:
            logger.error(f"Error handling Databricks callback: {str(e)}")
            return None
    
    def get_databricks_token(self) -> Optional[str]:
        """Get the current Databricks access token"""
        return st.session_state.get("databricks_token")
    
    def logout(self):
        """Clear all authentication tokens and user info"""
        keys_to_clear = [
            "microsoft_token",
            "microsoft_user_info", 
            "databricks_token",
            "databricks_token_type",
            "conversation_id",
            "chat_history"
        ]
        
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]
        
        # Also delete the token file to prevent auto-restore for different users
        try:
            import tempfile
            temp_dir = tempfile.gettempdir()
            token_file = os.path.join(temp_dir, f"streamlit_auth_{os.getpid()}.json")
            
            if os.path.exists(token_file):
                os.remove(token_file)
                logger.debug(f"Token file deleted: {token_file}")
        except Exception as e:
            logger.error(f"Failed to delete token file: {e}")
        
        # Force page refresh to clear any cached state
        st.rerun()
    
    def get_user_display_name(self) -> str:
        """Get user's display name from Microsoft user info"""
        user_info = st.session_state.get("microsoft_user_info", {})
        return user_info.get("displayName", user_info.get("userPrincipalName", "User"))


def handle_oauth_callback():
    """Handle OAuth callbacks from URL parameters"""
    auth_manager = AuthenticationManager()
    
    # Debug session state at the start of callback
    logger.debug("=== CALLBACK START - Session State Debug ===")
    logger.debug(f"Session state keys: {list(st.session_state.keys())}")
    for key in st.session_state.keys():
        if 'token' in key or 'microsoft' in key or 'databricks' in key:
            value = st.session_state[key]
            display_value = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
            logger.debug(f"  {key}: {display_value}")
    logger.debug("=" * 50)
    
    # Get URL parameters
    query_params = st.query_params
    
    if "code" in query_params and "state" in query_params:
        auth_code = query_params["code"]
        state = query_params["state"]
        
        if state == "microsoft_auth":
            # Handle Microsoft OAuth callback
            user_info = auth_manager.handle_microsoft_callback(auth_code)
            if user_info:
                st.success(f"Microsoft login successful! Welcome, {user_info.get('displayName', 'User')}")
                
                # Verify Microsoft token is properly stored
                microsoft_token = st.session_state.get("microsoft_token")
                logger.debug(f"After Microsoft callback - token stored: {'✓' if microsoft_token else '✗'}")
                
                if microsoft_token:
                    # Clear URL parameters AFTER verifying session state
                    st.query_params.clear()
                    databricks_auth_url = auth_manager.get_databricks_auth_url()
                    if databricks_auth_url:
                        st.info("Redirecting to Databricks authentication...")
                        # Use a more reliable redirect approach
                        st.markdown(f"""
                        <div style="text-align: center; margin: 2rem 0;">
                            <p>Please click the link below to continue to Databricks authentication:</p>
                            <a href="{databricks_auth_url}" target="_self" style="
                                background-color: #ff6b00;
                                color: white;
                                padding: 12px 24px;
                                text-decoration: none;
                                border-radius: 4px;
                                font-weight: bold;
                            ">Continue to Databricks</a>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.error("Failed to generate Databricks authentication URL")
                else:
                    st.error("Failed to store Microsoft token. Please try again.")
                    # Clear any partial session state
                    if "microsoft_token" in st.session_state:
                        del st.session_state["microsoft_token"]
                    if "microsoft_user_info" in st.session_state:
                        del st.session_state["microsoft_user_info"]
            else:
                st.error("Microsoft authentication failed. Please try again.")
                
        elif state == "databricks_auth":
            # Handle Databricks OAuth callback
            token = auth_manager.handle_databricks_callback(auth_code)
            if token:
                # DON'T clear query params immediately - it might interfere with session state
                st.success("Databricks authentication successful! Redirecting to chatbot...")
                
                # Verify both tokens are present before redirecting
                microsoft_token = st.session_state.get("microsoft_token")
                databricks_token = st.session_state.get("databricks_token")
                
                logger.debug(f"Before redirect - Microsoft token: {'✓' if microsoft_token else '✗'}")
                logger.debug(f"Before redirect - Databricks token: {'✓' if databricks_token else '✗'}")
                
                if microsoft_token and databricks_token:
                    # Both tokens present, safe to redirect
                    st.query_params.clear()
                    st.rerun()
                else:
                    st.error("Authentication incomplete. Microsoft token missing. Please try again.")
                    st.query_params.clear()
                    if "microsoft_token" in st.session_state:
                        del st.session_state["microsoft_token"]
                    if "databricks_token" in st.session_state:
                        del st.session_state["databricks_token"]
            else:
                st.error("Databricks authentication failed. Please try again.")
    
    return False  # No callback was handled


def show_login_page():
    """Display the login page with Microsoft SSO button"""
    auth_manager = AuthenticationManager()
    
    # Handle OAuth callbacks first
    callback_handled = handle_oauth_callback()
    
    # If callback was handled, don't show the login form
    if callback_handled:
        return
    
    st.title("🤖 Databricks Genie Chatbot")
    st.markdown("### Please sign in to continue")
    
    # Show current port and redirect URI information
    with st.expander("🔧 Configuration Info", expanded=False):
        expected_redirect = auth_manager.redirect_uri
        
        st.info(f"""
        **App is running on:** http://localhost:8505 (check terminal for actual port)
        **Expected Redirect URI:** {expected_redirect}
        
        ⚠️ **Important:** If these don't match, you need to:
        1. Update your `.env` file: `REDIRECT_URI=http://localhost:8505`
        2. Update your Azure App Registration redirect URI to: `http://localhost:8505`
        3. Update your Databricks OAuth app redirect URI to: `http://localhost:8505`
        """)
        
        if "localhost:8505" not in expected_redirect:
            st.error("❌ Redirect URI mismatch detected! Please update your configuration.")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 2rem; background-color: #0078d4; border-radius: 10px; margin: 2rem 0; color: white;">
            <h4 style="color: white;">Sign in with your Microsoft account</h4>
            <p style="color: white;">You'll be redirected to Microsoft login, then to Databricks authentication</p>
        </div>
        """, unsafe_allow_html=True)
        
        microsoft_auth_url = auth_manager.get_microsoft_auth_url()
        
        if microsoft_auth_url:
            st.markdown(f"""
            <div style="text-align: center; margin: 2rem 0;">
                <a href="{microsoft_auth_url}" target="_self">
                    <button style="
                        background-color: #0078d4;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        font-size: 16px;
                        border-radius: 4px;
                        cursor: pointer;
                        text-decoration: none;
                        display: inline-block;
                    ">
                        🔑 Sign in with Microsoft
                    </button>
                </a>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.error("Error generating authentication URL. Please check your configuration.")


def show_user_info():
    """Display user information and logout option"""
    auth_manager = AuthenticationManager()
    user_name = auth_manager.get_user_display_name()
    
    # Get detailed user info for debugging
    user_info = st.session_state.get("microsoft_user_info", {})
    user_email = user_info.get("userPrincipalName", "N/A")
    
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 Current User")
        st.markdown(f"**Name:** {user_name}")
        st.markdown(f"**Email:** {user_email}")
        st.markdown(f"**Auth Method:** OAuth")
        
        if st.button("🚪 Logout", help="Sign out and clear all cached tokens"):
            auth_manager.logout()
            st.rerun()
