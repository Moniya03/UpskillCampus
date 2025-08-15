import streamlit as st
import database as db
import security
import utils

# --- STREAMLIT UI ---

def login_screen():
    """Handles the login and initial setup UI."""
    st.header("🔐 Password Manager")

    if not db.check_master_user_exists():
        st.subheader("First Time Setup")
        st.info("Create a master password. This will be the only password you need to remember.")
        with st.form("setup_form"):
            new_password = st.text_input("Create Master Password", type="password")
            confirm_password = st.text_input("Confirm Master Password", type="password")
            submitted = st.form_submit_button("Create Vault")

            if submitted:
                if new_password and new_password == confirm_password:
                    db.create_master_user(new_password)
                    st.success("Vault created! Please log in.")
                    st.rerun()
                else:
                    st.error("Passwords do not match or are empty.")
    else:
        st.subheader("Unlock Vault")
        with st.form("login_form"):
            master_password = st.text_input("Enter Master Password", type="password", key="login_password")
            submitted = st.form_submit_button("Unlock")

            if submitted:
                key = db.verify_master_password(master_password)
                if key:
                    st.session_state['logged_in'] = True
                    st.session_state['encryption_key'] = key
                    st.rerun()
                else:
                    st.error("Incorrect master password.")

def main_app():
    """The main application interface after login."""
    st.sidebar.title(f"Welcome!")
    st.sidebar.markdown("---")
    
    action = st.sidebar.radio(
        "Choose an action", 
        ["View & Search Passwords", "Add New Password", "Update Password", "Delete Password"]
    )
    
    key = st.session_state['encryption_key']

    if action == "Add New Password":
        st.subheader("Add a New Password")
        
        # --- Password Generator ---
        st.markdown("#### Password Generator")
        col1, col2, col3 = st.columns([1,1,1])
        length = col1.slider("Length", 8, 32, 16)
        inc_numbers = col2.checkbox("Numbers", True)
        inc_symbols = col3.checkbox("Symbols", True)
        
        if st.button("Generate Secure Password"):
            st.session_state.generated_password = utils.generate_password(length, inc_symbols, inc_numbers)
        
        generated_password_value = st.session_state.get('generated_password', '')
        
        with st.form("add_form", clear_on_submit=True):
            service = st.text_input("Service Name (e.g., Google)")
            username = st.text_input("Username / Email")
            password = st.text_input("Password", type="password", value=generated_password_value)
            submitted = st.form_submit_button("Add Password")

            if submitted and service and username and password:
                encrypted_data = security.encrypt_data({'username': username, 'password': password}, key)
                if db.add_password(service, encrypted_data):
                    st.success(f"Password for '{service}' added successfully!")
                    if 'generated_password' in st.session_state:
                         del st.session_state['generated_password']
                else:
                    st.error(f"Service '{service}' already exists.")
            elif submitted:
                st.warning("Please fill in all fields.")

    elif action == "View & Search Passwords":
        st.subheader("Your Stored Passwords")
        
        # --- Search Functionality ---
        search_term = st.text_input("Search for a service")
        
        all_services = db.get_all_services()
        if not all_services:
            st.info("Your vault is empty. Add a password to get started.")
        else:
            filtered_services = [s for s in all_services if search_term.lower() in s.lower()]
            
            if not filtered_services:
                st.warning(f"No services found matching '{search_term}'.")
            else:
                for service in filtered_services:
                    with st.expander(service):
                        encrypted_data = db.get_encrypted_data(service)
                        decrypted_creds = security.decrypt_data(encrypted_data, key)
                        if decrypted_creds:
                            # --- UPDATED CODE ---
                            # Use st.code() which has a built-in copy button
                            st.write("**Username:**")
                            st.code(decrypted_creds['username'], language=None)
                            
                            st.write("**Password:**")
                            st.code(decrypted_creds['password'], language=None)
                        else:
                            st.error("Decryption failed.")

    elif action == "Update Password":
        st.subheader("Update an Existing Password")
        all_services = db.get_all_services()
        if not all_services:
            st.info("Your vault is empty.")
        else:
            service_to_update = st.selectbox("Select a service to update", options=all_services)
            
            encrypted_data = db.get_encrypted_data(service_to_update)
            current_creds = security.decrypt_data(encrypted_data, key)

            if current_creds:
                with st.form("update_form"):
                    st.write(f"Updating credentials for **{service_to_update}**")
                    new_username = st.text_input("New Username / Email", value=current_creds['username'])
                    new_password = st.text_input("New Password", type="password", key="update_pw")
                    
                    # --- Password Strength Meter ---
                    if new_password:
                        strength, score, _ = utils.check_password_strength(new_password)
                        st.progress(score / 6)
                        st.write(f"Password Strength: **{strength}**")

                    submitted = st.form_submit_button("Update Password")
                    if submitted:
                        # Ensure new password is not empty before updating
                        if not new_password:
                            st.warning("Password cannot be empty.")
                        else:
                            new_encrypted_data = security.encrypt_data(
                                {'username': new_username, 'password': new_password}, key
                            )
                            db.update_password(service_to_update, new_encrypted_data)
                            st.success(f"Password for '{service_to_update}' updated successfully!")

    elif action == "Delete Password":
        st.subheader("Delete a Password")
        all_services = db.get_all_services()
        if not all_services:
            st.info("Your vault is empty.")
        else:
            service_to_delete = st.selectbox("Select a service to delete", options=all_services, key="delete_select")
            if st.button(f"Delete '{service_to_delete}'", type="primary"):
                db.delete_password(service_to_delete)
                st.warning(f"Password for '{service_to_delete}' has been deleted.")
                st.rerun()

    st.sidebar.markdown("---")
    if st.sidebar.button("Lock Vault"):
        for key_session in list(st.session_state.keys()):
            del st.session_state[key_session]
        st.rerun()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    st.set_page_config(page_title="Password Manager", layout="centered")
    db.setup_database()

    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if st.session_state['logged_in']:
        main_app()
    else:
        login_screen()
