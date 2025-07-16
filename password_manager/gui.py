import sys
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel,
    QLineEdit, QPushButton, QListWidget, QMessageBox,
    QHBoxLayout, QInputDialog, QCheckBox, QSpacerItem, QSizePolicy, QSpinBox
)
import threading
import time
import uvicorn
import os


API_URL = "http://loaclhost:8000"  # Change this if needed (e.g., to localhost)

class PasswordManagerClient(QWidget):
    def __init__(self):
        super().__init__()
        self.token = None
        self.passwords = []  # local cache of passwords with id
        self.show_passwords = False
        self.is_admin = False  # Will be set after login
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Manager Client")

        self.layout = QVBoxLayout()

        self.label = QLabel("Login")
        self.layout.addWidget(self.label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        btn_layout = QHBoxLayout()

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.login)
        btn_layout.addWidget(self.login_btn)

        self.register_btn = QPushButton("Register")
        self.register_btn.clicked.connect(self.register)
        btn_layout.addWidget(self.register_btn)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        self.logout_btn.setEnabled(False)
        btn_layout.addWidget(self.logout_btn)

        self.layout.addLayout(btn_layout)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search services, URLs or usernames")
        self.search_input.textChanged.connect(self.filter_passwords)
        self.search_input.setEnabled(False)
        self.layout.addWidget(self.search_input)

        self.pwd_list = QListWidget()
        self.pwd_list.itemClicked.connect(self.copy_selected_password_to_clipboard)
        self.layout.addWidget(self.pwd_list)

        pw_btn_layout = QHBoxLayout()

        self.add_btn = QPushButton("Add Password")
        self.add_btn.clicked.connect(self.add_password)
        self.add_btn.setEnabled(False)
        pw_btn_layout.addWidget(self.add_btn)

        self.edit_btn = QPushButton("Edit Password")
        self.edit_btn.clicked.connect(self.edit_password)
        self.edit_btn.setEnabled(False)
        pw_btn_layout.addWidget(self.edit_btn)

        self.delete_btn = QPushButton("Delete Password")
        self.delete_btn.clicked.connect(self.delete_password)
        self.delete_btn.setEnabled(False)
        pw_btn_layout.addWidget(self.delete_btn)

        self.toggle_pwd_cb = QCheckBox("Show Passwords")
        self.toggle_pwd_cb.stateChanged.connect(self.toggle_passwords)
        self.toggle_pwd_cb.setEnabled(False)
        pw_btn_layout.addWidget(self.toggle_pwd_cb)

        spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        pw_btn_layout.addSpacerItem(spacer)

        self.layout.addLayout(pw_btn_layout)

        self.add_password_generator_ui()

        self.setLayout(self.layout)

    def add_admin_button(self):
        if hasattr(self, 'admin_btn'):
            return  # Prevent duplicate buttons
        self.admin_btn = QPushButton("🔍 Admin: Search User Login")
        self.admin_btn.clicked.connect(self.show_admin_user_password)
        # Insert before password generator controls (last layout)
        self.layout.insertWidget(self.layout.count() - 1, self.admin_btn)

    def set_ui_enabled(self, enabled: bool):
        self.username_input.setEnabled(not enabled)
        self.password_input.setEnabled(not enabled)
        self.login_btn.setEnabled(not enabled)
        self.register_btn.setEnabled(not enabled)
        self.logout_btn.setEnabled(enabled)
        self.search_input.setEnabled(enabled)
        self.add_btn.setEnabled(enabled)
        self.edit_btn.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)
        self.toggle_pwd_cb.setEnabled(enabled)
        if hasattr(self, 'admin_btn'):
            self.admin_btn.setEnabled(enabled and self.is_admin)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password required")
            return
        self.set_ui_enabled(False)
        try:
            response = requests.post(f"{API_URL}/token", data={"username": username, "password": password})
            response.raise_for_status()
            self.token = response.json()["access_token"]
            self.label.setText(f"Logged in as {username}")
            # Determine if user is admin
            self.is_admin = (username == "admin")
            if self.is_admin:
                self.add_admin_button()
            self.set_ui_enabled(True)
            self.load_passwords()
        except Exception as e:
            self.set_ui_enabled(True)
            QMessageBox.warning(self, "Error", f"Login failed: {e}")

    def register(self):
        username, ok1 = QInputDialog.getText(self, "Register", "Enter username:")
        if not ok1 or not username:
            return
        password, ok2 = QInputDialog.getText(self, "Register", "Enter password:", QLineEdit.Password)
        if not ok2 or not password:
            return

        self.set_ui_enabled(False)
        try:
            response = requests.post(f"{API_URL}/register", json={"username": username, "password": password})
            response.raise_for_status()
            QMessageBox.information(self, "Success", "User registered! You can now login.")
        except requests.HTTPError as he:
            if he.response.status_code == 400:
                QMessageBox.warning(self, "Error", "Username already registered")
            else:
                QMessageBox.warning(self, "Error", f"Registration failed: {he}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Registration failed: {e}")
        finally:
            self.set_ui_enabled(True)

    def logout(self):
        self.token = None
        self.label.setText("Login")
        self.pwd_list.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.set_ui_enabled(False)
        # Remove admin button on logout if exists
        if hasattr(self, 'admin_btn'):
            self.admin_btn.deleteLater()
            del self.admin_btn
        self.is_admin = False

    def load_passwords(self):
        if not self.token:
            return
        self.set_ui_enabled(False)
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{API_URL}/passwords/", headers=headers)
            response.raise_for_status()
            self.passwords = response.json()  # keep full list
            self.filter_passwords()
            self.set_ui_enabled(True)
        except Exception as e:
            self.set_ui_enabled(True)
            QMessageBox.warning(self, "Error", f"Failed to load passwords: {e}")

    def filter_passwords(self):
        search = self.search_input.text().lower()
        self.pwd_list.clear()
        for pwd in self.passwords:
            if (search in pwd['service'].lower() or
                search in pwd['username'].lower() or
                search in (pwd.get('url') or '').lower()):
                url = pwd.get('url') or ''
                displayed_password = pwd['password'] if self.show_passwords else '*' * len(pwd['password'])
                self.pwd_list.addItem(f"{pwd['service']} | {url} | {pwd['username']} | {displayed_password}")

    def toggle_passwords(self):
        self.show_passwords = self.toggle_pwd_cb.isChecked()
        self.filter_passwords()

    def add_password(self):
        if not self.token:
            QMessageBox.warning(self, "Error", "Please login first")
            return

        service, ok1 = QInputDialog.getText(self, "Add Password", "Service:")
        if not ok1 or not service:
            return

        url, ok_url = QInputDialog.getText(self, "Add Password", "URL:")
        if not ok_url or not url:
            return

        username, ok2 = QInputDialog.getText(self, "Add Password", "Username:")
        if not ok2 or not username:
            return

        password, ok3 = QInputDialog.getText(self, "Add Password", "Password:", QLineEdit.Password)
        if not ok3 or not password:
            return

        self.set_ui_enabled(False)
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            data = {
                "service": service,
                "url": url,
                "username": username,
                "password": password
            }
            response = requests.post(f"{API_URL}/passwords/", json=data, headers=headers)

            if response.status_code not in (200, 201):
                raise Exception(f"Unexpected status code: {response.status_code}")

            QMessageBox.information(self, "Success", "Password added successfully")
            self.load_passwords()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add password: {e}")
        finally:
            self.set_ui_enabled(True)

    def get_selected_password(self):
        selected_items = self.pwd_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "Please select a password entry")
            return None
        selected_text = selected_items[0].text()
        # parse service, url and username from the displayed string: "service | url | username | *****"
        parts = selected_text.split(" | ")
        if len(parts) < 3:
            return None
        service, url, username = parts[0], parts[1], parts[2]
        # Find password id by matching service, url, and username from self.passwords
        for pwd in self.passwords:
            if pwd['service'] == service and pwd['url'] == url and pwd['username'] == username:
                return pwd
        return None

    def edit_password(self):
        pwd = self.get_selected_password()
        if not pwd:
            return
        new_username, ok1 = QInputDialog.getText(self, "Edit Password", "Username:", text=pwd['username'])
        if not ok1 or not new_username:
            return
        new_password, ok2 = QInputDialog.getText(self, "Edit Password", "Password:", QLineEdit.Password, text=pwd['password'])
        if not ok2 or not new_password:
            return
        self.set_ui_enabled(False)
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            data = {"service": pwd['service'], "url": pwd['url'], "username": new_username, "password": new_password}
            response = requests.put(f"{API_URL}/passwords/{pwd['id']}", json=data, headers=headers)
            response.raise_for_status()
            QMessageBox.information(self, "Success", "Password updated")
            self.load_passwords()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to update password: {e}")
        finally:
            self.set_ui_enabled(True)

    def delete_password(self):
        pwd = self.get_selected_password()
        if not pwd:
            return
        confirm = QMessageBox.question(self, "Confirm Delete", f"Delete password for service '{pwd['service']}'?", QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        self.set_ui_enabled(False)
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.delete(f"{API_URL}/passwords/{pwd['id']}", headers=headers)
            response.raise_for_status()
            QMessageBox.information(self, "Success", "Password deleted")
            self.load_passwords()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to delete password: {e}")
        finally:
            self.set_ui_enabled(True)

    def copy_selected_password_to_clipboard(self):
        pwd = self.get_selected_password()
        if not pwd:
            return
        text_to_copy = f"Service: {pwd['service']}\nURL: {pwd['url']}\nUsername: {pwd['username']}\nPassword: {pwd['password']}"
        QApplication.clipboard().setText(text_to_copy)
        QMessageBox.information(self, "Copied", "Password details copied to clipboard")

    def add_password_generator_ui(self):
        # --- Password Length SpinBox ---
        self.length_label = QLabel("Password Length:")
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setMinimum(8)
        self.length_spinbox.setMaximum(64)
        self.length_spinbox.setValue(10)

        # --- Special Characters Checkbox ---
        self.special_char_checkbox = QCheckBox("Include Special Characters")
        self.special_char_checkbox.setChecked(True)

        # --- Generate Button ---
        self.generate_password_btn = QPushButton("Generate Password")
        self.generate_password_btn.clicked.connect(self.handle_generate_password)

        # --- Layout for Password Generator Controls ---
        generator_layout = QHBoxLayout()
        generator_layout.addWidget(self.length_label)
        generator_layout.addWidget(self.length_spinbox)
        generator_layout.addWidget(self.special_char_checkbox)
        generator_layout.addWidget(self.generate_password_btn)

        # Add to form or vertical layout
        self.layout.addLayout(generator_layout)

    def handle_generate_password(self):
        try:
            length = self.length_spinbox.value()
            use_special = self.special_char_checkbox.isChecked()
            res = requests.get(f"{API_URL}/generate-password?length={length}&use_special={use_special}")
            res.raise_for_status()
            generated_password = res.json()["generated_password"]

            # Auto-fill password input field
            self.password_input.setText(generated_password)

            # Copy to clipboard
            QApplication.clipboard().setText(generated_password)

            QMessageBox.information(self, "Password Generated", "A strong password has been generated and copied to clipboard.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate password:\n{str(e)}")

    def show_admin_user_password(self):
        if not self.token or not self.is_admin:
            QMessageBox.warning(self, "Access Denied", "Admin privileges required.")
            return

        username, ok = QInputDialog.getText(self, "Search User", "Enter username to fetch login password:")
        if not ok or not username:
            return

        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            params = {"username": username}
            res = requests.get(f"{API_URL}/admin/user-password", headers=headers, params=params)
            res.raise_for_status()
            data = res.json()

            msg = f"Username: {data['username']}\nLogin Password: {data['password']}"
            QMessageBox.information(self, "User Login Password", msg)

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                QMessageBox.warning(self, "Not Found", f"User '{username}' not found.")
            else:
                QMessageBox.critical(self, "Error", f"Failed to fetch user password:\n{str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error:\n{str(e)}")
    
import sys
from PyQt5.QtWidgets import QApplication
from gui import PasswordManagerClient  

def main():
    app = QApplication(sys.argv)
    window = PasswordManagerClient()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

