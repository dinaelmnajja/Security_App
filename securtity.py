import sys
import hashlib
import requests
import base64
import re
from PyQt5 import QtCore, QtGui, QtWidgets, uic
from PyQt5.QtWidgets import QMessageBox, QFileDialog, QMainWindow

# Sample known malware hashes for demonstration purposes
KNOWN_MALWARE_HASHES = {
    "5d41402abc4b2a76b9719d911017c592",  # Example hash for "hello"
    "098f6bcd4621d373cade4e832627b4f6"   # Example hash for "test"
}


# Replace this with your actual VirusTotal API Key
VIRUSTOTAL_API_KEY = "70834524a969e762a593a070d8f6912dfff8fe0f40b96b7c147f5c6b055d0426"
class MainApp(QMainWindow):
    
    def __init__(self):
        super().__init__()  # Correctly call the superclass initializer
        uic.loadUi("cyber_app.ui", self)
        
        # Connect the buttons to their functions
        self.pushButton.clicked.connect(self.hash_md5)
        self.pushButton_4.clicked.connect(self.hash_sha1)
        self.pushButton_2.clicked.connect(self.scan_file)
        self.pushButton_3.clicked.connect(self.check_link)
        self.pushButton_5.clicked.connect(self.check_email) 

    def scan_file(self):
        """Scan a selected file for malware."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file_path:
            file_hash = self.compute_md5(file_path)
            if file_hash in KNOWN_MALWARE_HASHES:
                QMessageBox.warning(self, "Malware Detected", f"The file '{file_path}' is identified as malware.")
            else:
                QMessageBox.information(self, "Scan Complete", f"The file '{file_path}' is clean.")

    def compute_md5(self, file_path):
        """Compute the MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def check_link(self):
        """Check a link for malware using VirusTotal API."""
        try:
           link = self.plainTextEdit_2.toPlainText()
           if link:
            # Submit the URL for analysis
            scan_id = self.submit_url_for_analysis(link)
            if scan_id:
                # Retrieve the analysis results
                results = self.get_analysis_results(scan_id)
                if results:
                    print(f"Full JSON Response: {results}")
                    # Ensure 'data' and 'attributes' keys exist
                    if 'data' in results and 'attributes' in results['data']:
                        last_analysis_stats = results['data']['attributes'].get('last_analysis_stats', {})
                        malicious_count = last_analysis_stats.get('malicious', 0)
                        if malicious_count > 0:
                            QMessageBox.warning(self, "Malware Detected", "The link is identified as malicious.")
                        else:
                            QMessageBox.information(self, "Scan Complete", "The link is clean.")
                    else:
                        QMessageBox.warning(self, "Error", "The analysis results do not contain expected data.")
            else:
                QMessageBox.warning(self, "Error", "Failed to submit URL for analysis.")
           else:
               QMessageBox.warning(self, "Input Error", "Please enter a link to check.")
        except Exception as e:
             QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def submit_url_for_analysis(self, url):
        """Submit the URL for analysis and return the scan ID."""
        try:
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.post(f"https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            if response.status_code == 200:
                print(f"URL Submission Response: {response.json()}")
                return response.json()['data']['id']
            else:
                QMessageBox.warning(self, "Error", f"Failed to submit URL: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            return None

    def get_analysis_results(self, scan_id):
        """Retrieve the analysis results using the scan ID."""
        try:
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            if response.status_code == 200:
                print(f"Analysis Results Response: {response.json()}")
                return response.json()
            else:
                QMessageBox.warning(self, "Error", f"Failed to retrieve analysis results: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            return None         


        

    def hash_md5(self):
        try:
            input_text = self.findChild(QtWidgets.QPlainTextEdit, "plainTextEdit").toPlainText()
            if input_text:
                hash_object = hashlib.md5(input_text.encode())
                hash_text = hash_object.hexdigest()
                self.findChild(QtWidgets.QPlainTextEdit, "plainTextEdit_3").setPlainText(hash_text)
            else:
                QMessageBox.warning(self, "Input Error", "Please enter text to hash.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def hash_sha1(self):
        try:
            input_text = self.findChild(QtWidgets.QPlainTextEdit, "plainTextEdit").toPlainText()
            if input_text:
                hash_object = hashlib.sha1(input_text.encode())
                hash_text = hash_object.hexdigest()
                self.findChild(QtWidgets.QPlainTextEdit, "plainTextEdit_3").setPlainText(hash_text)
            else:
                QMessageBox.warning(self, "Input Error", "Please enter text to hash.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")


    

    
    def check_email(self):
        email = self.plainTextEdit_4.toPlainText().strip()


        if not email:
           self.show_message("Input Error", "Please enter an email to check.")
       
        
        elif self.is_phishing(email):
            self.show_message("STATUS", f"{email} is PHISHING")

        else:
            self.show_message("STATUS", f"{email} is SAFE")
        
          

    def is_phishing(self, email):
        # List of known phishing domains (update with more domains as needed)
        phishing_domains = ["examplephishing.com", "maliciousdomain.com"]

        # Basic regex pattern for email validation
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

        # Extract domain from email
        domain = email.split('@')[-1]

        # Check if domain is in the list of known phishing domains
        if domain in phishing_domains:
            return True

        # Check if email matches basic pattern
        if not email_pattern.match(email):
            return True

        # Additional checks to reduce false positives
        # Avoid domain-specific checks that are overly aggressive
        if len(domain.split('.')) < 2:  # Ensure domain has at least one dot
            return True

        # No additional suspicious patterns
        return False

    def show_message(self, title, message):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()
        

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    main_app = MainApp()
    main_app.show()
    sys.exit(app.exec_())
