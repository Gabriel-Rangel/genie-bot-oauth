import os
import streamlit as st
import asyncio
import json
import base64
from typing import Dict, Optional
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.dashboards import GenieAPI
import requests
from dotenv import load_dotenv
import logging

# Import our authentication module
from auth import AuthenticationManager, show_login_page, show_user_info

# Load environment variables from .env file
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configuration
space_id = os.getenv("GENIE_SPACE_ID")
databricks_host = os.getenv("DATABRICKS_HOST")

# Initialize authentication manager
auth_manager = AuthenticationManager()


def get_databricks_client():
    """Get authenticated Databricks client"""
    # Get OAuth token from session state
    token = st.session_state.get("databricks_token")
    if not token:
        logger.error("No Databricks token found in session state")
        return None
    
    logger.debug("Using OAuth token for authentication")
    # Use token-based authentication explicitly
    return WorkspaceClient(
        host=databricks_host,
        token=token
    )

def get_query_results(conversation_id, message_id, token=None):
    """Get query results from Databricks API"""
    # Use provided token or get OAuth token from session state
    if not token:
        token = st.session_state.get("databricks_token")
        if not token:
            logger.error("No Databricks token found in session state")
            raise Exception("No valid Databricks token available")
        logger.debug("Using OAuth token for query results")
    
    hostname = databricks_host.replace("https://", "").replace("http://", "")
    url = f"https://{hostname}/api/2.0/genie/spaces/{space_id}/conversations/{conversation_id}/messages/{message_id}/query-result"
    response = requests.get(url, headers={'Authorization': f'Bearer {token}'})
    return response.json()

# Helper functions (ask_genie and process_query_results remain the same)
async def ask_genie(question: str, space_id: str, conversation_id: Optional[str] = None) -> tuple[str, str]:
    try:
        logger.debug(f"ask_genie called with space_id: {space_id}")
        logger.debug(f"databricks_host: {databricks_host}")
        
        # Get OAuth token from session state
        token = st.session_state.get("databricks_token")
        if not token:
            logger.error("No Databricks token found in session state")
            raise Exception("No valid Databricks token available")
        
        # Decode JWT payload (without verification since we just want to see the scope)
        try:
            # JWT has 3 parts separated by dots: header.payload.signature
            payload_part = token.split('.')[1]
            # Add padding if needed
            payload_part += '=' * (4 - len(payload_part) % 4)
            decoded_payload = base64.b64decode(payload_part)
            token_info = json.loads(decoded_payload)
            logger.debug(f"Token scope: {token_info.get('scope', 'not found')}")
            logger.debug(f"Token subject: {token_info.get('sub', 'not found')}")
            logger.debug(f"Token audience: {token_info.get('aud', 'not found')}")
            logger.debug(f"Token client_id: {token_info.get('client_id', 'not found')}")
        except Exception as e:
            logger.debug(f"Could not decode token: {e}")
        
        # Get authenticated Databricks client
        workspace_client = get_databricks_client()
        if not workspace_client:
            logger.error("No valid Databricks authentication available")
            raise Exception("No valid Databricks authentication available")
        
        logger.debug("Databricks client created successfully")
        genie_api = GenieAPI(workspace_client.api_client)
        logger.debug("GenieAPI initialized successfully")
        
        loop = asyncio.get_running_loop()
        if conversation_id is None:
            logger.debug("Starting new conversation...")
            initial_message = await loop.run_in_executor(None, genie_api.start_conversation_and_wait, space_id, question)
            conversation_id = initial_message.conversation_id
            logger.debug(f"New conversation started with ID: {conversation_id}")
        else:
            logger.debug(f"Adding message to existing conversation: {conversation_id}")
            initial_message = await loop.run_in_executor(None, genie_api.create_message_and_wait, space_id, conversation_id, question)

        query_result = None
        if initial_message.query_result is not None:
            query_result = await loop.run_in_executor(None, genie_api.get_message_query_result,
                space_id, initial_message.conversation_id, initial_message.id)

        message_content = await loop.run_in_executor(None, genie_api.get_message,
            space_id, initial_message.conversation_id, initial_message.id)

        if query_result and query_result.statement_response:
            results = await loop.run_in_executor(None, get_query_results,
                initial_message.conversation_id, initial_message.id, token)
            logger.info(f"results: {str(results)}")
            
            query_description = ""
            for attachment in message_content.attachments:
                if attachment.query and attachment.query.description:
                    query_description = attachment.query.description
                    break

            return json.dumps({
                "columns": results['statement_response']['manifest']['schema']['columns'],
                "data": results['statement_response']['result']['data_typed_array'],
                "query_description": query_description
            }), conversation_id

        if message_content.attachments:
            for attachment in message_content.attachments:
                if attachment.text and attachment.text.content:
                    return json.dumps({"message": attachment.text.content}), conversation_id

        return json.dumps({"message": message_content.content}), conversation_id
    except Exception as e:
        logger.error(f"Error in ask_genie: {str(e)}")
        logger.error(f"Full error details: {type(e).__name__}: {e}")
        
        # Return more detailed error information
        error_details = {
            "error": f"Error: {str(e)}",
            "error_type": type(e).__name__,
            "space_id": space_id,
            "databricks_host": databricks_host
        }
        return json.dumps(error_details), conversation_id

def process_query_results(answer_json: Dict) -> str:
    response = ""
    logger.debug(f"answer_json: {str(answer_json)}")
    
    if "error" in answer_json:
        response += f"❌ **Erro:** {answer_json.get('error', 'Erro desconhecido')}\n\n"
        
        if "error_type" in answer_json:
            response += f"**Tipo:** {answer_json['error_type']}\n\n"
        
        return response
    
    if "query_description" in answer_json and answer_json["query_description"]:
        response += f"## Descrição da Consulta\n\n{answer_json['query_description']}\n\n"

    if "columns" in answer_json and "data" in answer_json:
        response += "## Resultados da Consulta\n\n"
        columns = answer_json["columns"]
        data = answer_json["data"]
        if len(data) > 0: 
            header = "| " + " | ".join(col['name'] for col in columns) + " |"
            separator = "|" + "|".join(["---" for _ in columns]) + "|"
                
            response += header + "\n" + separator + "\n"
                
            for row in data:
                formatted_row = []
                for value, col_schema in zip(row['values'], columns):
                    if value is None or value.get('str') is None:
                        formatted_value = "NULL"
                    elif col_schema['type_name'] in ['DECIMAL', 'DOUBLE', 'FLOAT']:
                        formatted_value = f"{float(value['str']):,.2f}"
                    elif col_schema['type_name'] in ['INT', 'BIGINT']:
                        formatted_value = f"{int(value['str']):,}"
                    else:
                        formatted_value = value['str']
                    formatted_row.append(formatted_value)
                response += "| " + " | ".join(formatted_row) + " |\n"
        else:
            response += f"Nenhum resultado encontrado.\n\n"
    elif "message" in answer_json:
        response += f"{answer_json['message']}\n\n"
    else:
        response += "No data available.\n\n"
    
    return response

def submit_question():
    st.session_state.processing = True


def main():
    # Debug session state at the very start of main
    logger.debug("=== MAIN START - Session State Debug ===")
    logger.debug(f"Session state keys: {list(st.session_state.keys())}")
    for key in st.session_state.keys():
        if 'token' in key or 'microsoft' in key or 'databricks' in key:
            value = st.session_state[key]
            display_value = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
            logger.debug(f"  {key}: {display_value}")
    logger.debug("=" * 50)
    
    # Check authentication
    logger.debug("Starting main() - checking authentication...")
    authenticated = auth_manager.is_authenticated()
    
    logger.debug(f"Authentication status: {'✓ Authenticated' if authenticated else '✗ Not authenticated'}")
    
    if not authenticated:
        logger.debug("Showing login page...")
        show_login_page()
        return
    
    logger.debug("User is authenticated - showing chatbot interface")
    # Show user info in sidebar
    show_user_info()

    if 'conversation_id' not in st.session_state:
        st.session_state.conversation_id = None

    # Streamlit UI
    st.title("Chatbot powered by Genie")

    # Initialize session state for chat history
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []

    if "processing" not in st.session_state:
        st.session_state.processing = False

    # Display chat history
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # User input
    user_input = st.chat_input("Digite sua mensagem aqui...", on_submit=submit_question, disabled=st.session_state.processing)


    if user_input:# and not st.session_state.processing:
        # Add user message to chat history
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Get bot response
        with st.chat_message("assistant"):
            st.session_state.processing = True

            message_placeholder = st.empty()
            message_placeholder.markdown("Thinking...")

            try:
                logger.info(f"Conversation_id: {str(st.session_state.conversation_id)}")
                answer, new_conversation_id = asyncio.run(ask_genie(user_input, space_id, st.session_state.conversation_id))
                st.session_state.conversation_id = new_conversation_id
                
                logger.info(f"New conversation_id: {str(st.session_state.conversation_id)}")
                answer_json = json.loads(answer)
                response = process_query_results(answer_json)
                message_placeholder.markdown(response)
                # Add bot response to chat history
                st.session_state.chat_history.append({"role": "assistant", "content": response})
                st.session_state.processing = False
            except Exception as e:
                logger.error(f"Error processing message: {str(e)}")
                message_placeholder.markdown("An error occurred while processing your request.")
                st.session_state.processing = False
            st.rerun()


    # Clear chat button
    if st.sidebar.button("Clear Chat"):
        st.session_state.chat_history = []
        st.session_state.processing = False
        st.rerun()

if __name__ == "__main__":
    main()