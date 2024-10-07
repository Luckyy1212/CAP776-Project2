import bcrypt
import csv
import re
import requests
import json
import random
import string
from datetime import datetime
from getpass import getpass
import os

# Constants
MAX_LOGIN_ATTEMPTS = 5
CSV_FILE = 'regno.csv'
HISTORY_FILE = 'user_history.csv'
API_KEY = 'your_openweather_api_key'  # Replace with your actual API key

class AirQualityMonitor:
    def __init__(self):
        self.login_attempts = 0
        self.create_csv_files()

    def create_csv_files(self):
        """Create necessary CSV files if they don't exist"""
        # Create regno.csv for user credentials
        if not os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['email', 'password', 'security_question', 'security_answer'])

        # Create history.csv for user activity tracking
        if not os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'email', 'action', 'details'])

    def check_if_users_exist(self):
        """Check if any users are registered in the system"""
        try:
            with open(CSV_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                return any(reader)
        except Exception as e:
            print(f"Error checking users: {e}")
            return False

    def generate_captcha(self):
        """Generate a random 6-character captcha"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    def verify_captcha(self, generated_captcha):
        """Verify user-entered captcha"""
        while True:
            user_input = input(f"Enter the captcha ({generated_captcha}): ")
            if user_input.upper() == generated_captcha:
                return True
            print("Invalid captcha! Please try again.")
            return False

    def log_activity(self, email, action, details):
        """Log user activity to history file"""
        try:
            with open(HISTORY_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([datetime.now(), email, action, details])
        except Exception as e:
            print(f"Error logging activity: {e}")

    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_password(self, password):
        """
        Validate password complexity
        Returns: (bool, str) - (is_valid, message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, "Password is valid"

    def hash_password(self, password):
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def verify_password(self, password, hashed):
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        except Exception:
            return False

    def check_email_exists(self, email):
        """Check if email already exists in the system"""
        try:
            with open(CSV_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                return any(row[0] == email for row in reader)
        except Exception:
            return False

    def register_user(self):
        """Handle user registration process"""
        print("\n=== User Registration ===")
        print("\nPassword requirements:")
        print("- Minimum 8 characters")
        print("- At least one uppercase letter")
        print("- At least one lowercase letter")
        print("- At least one digit")
        print("- At least one special character (!@#$%^&*(),.?\":{}|<>)")

        # Email validation
        while True:
            email = input("\nEnter email: ").strip()
            if not self.validate_email(email):
                print("Invalid email format. Please try again.")
                continue
            if self.check_email_exists(email):
                print("This email is already registered. Please use a different email.")
                continue
            break

        # Password validation
        while True:
            password = getpass("Enter password: ")
            is_valid, message = self.validate_password(password)
            if not is_valid:
                print(f"Invalid password: {message}")
                continue
            
            confirm_password = getpass("Confirm password: ")
            if password != confirm_password:
                print("Passwords do not match. Please try again.")
                continue
            break

        # Security question
        print("\nSecurity Question Setup")
        print("This will be used to reset your password if you forget it.")
        security_question = input("Enter a security question: ").strip()
        security_answer = input("Enter the answer: ").strip()

        # Save user data
        try:
            with open(CSV_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    email,
                    self.hash_password(password).decode('utf-8'),
                    security_question,
                    security_answer
                ])
            self.log_activity(email, "REGISTRATION", "New user registered")
            print("\nRegistration successful!")
            print("You can now log in with your email and password.")
        except Exception as e:
            print(f"Error during registration: {e}")
            print("Please try again later.")

    def reset_password(self):
        """Handle password reset process"""
        print("\n=== Password Reset ===")
        email = input("Enter your registered email: ").strip()

        if not self.check_email_exists(email):
            print("Email not found in our records.")
            return

        # Find user data
        user_data = None
        try:
            with open(CSV_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if row[0] == email:
                        user_data = row
                        break
        except Exception as e:
            print(f"Error accessing user data: {e}")
            return

        # Verify security question
        print(f"\nSecurity Question: {user_data[2]}")
        answer = input("Enter your answer: ").strip()
        if answer.lower() != user_data[3].lower():
            print("Incorrect answer.")
            return

        # Set new password
        while True:
            new_password = getpass("\nEnter new password: ")
            is_valid, message = self.validate_password(new_password)
            if not is_valid:
                print(f"Invalid password: {message}")
                continue
            
            confirm_password = getpass("Confirm new password: ")
            if new_password != confirm_password:
                print("Passwords do not match. Please try again.")
                continue
            break

        # Update password in CSV
        try:
            users = []
            with open(CSV_FILE, 'r') as f:
                reader = csv.reader(f)
                users.append(next(reader))  # Header
                for row in reader:
                    if row[0] == email:
                        row[1] = self.hash_password(new_password).decode('utf-8')
                    users.append(row)

            with open(CSV_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(users)

            self.log_activity(email, "PASSWORD_RESET", "Password reset successful")
            print("\nPassword reset successful!")
            print("You can now log in with your new password.")
        except Exception as e:
            print(f"Error resetting password: {e}")
            print("Please try again later.")

    def login(self):
        """Handle user login process"""
        if not self.check_if_users_exist():
            print("\nNo registered users found!")
            print("Please register a new user first.")
            return False

        while self.login_attempts < MAX_LOGIN_ATTEMPTS:
            print("\n=== Login ===")
            email = input("Enter email (or 'forgot' for password reset): ").strip()
            
            if email.lower() == 'forgot':
                self.reset_password()
                return False

            password = getpass("Enter password: ")

            # Generate and verify captcha
            captcha = self.generate_captcha()
            if not self.verify_captcha(captcha):
                self.login_attempts += 1
                remaining = MAX_LOGIN_ATTEMPTS - self.login_attempts
                print(f"\nInvalid captcha. {remaining} attempts remaining.")
                continue

            # Verify credentials
            try:
                with open(CSV_FILE, 'r') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    for row in reader:
                        if row[0] == email and self.verify_password(password, row[1].encode('utf-8')):
                            print("\nLogin successful!")
                            self.log_activity(email, "LOGIN", "Successful login")
                            return email
                
                self.login_attempts += 1
                remaining = MAX_LOGIN_ATTEMPTS - self.login_attempts
                print(f"\nInvalid credentials. {remaining} attempts remaining.")
                if remaining > 0:
                    print("If you forgot your password, type 'forgot' as email.")
                self.log_activity(email, "LOGIN_FAILED", f"Failed attempt {self.login_attempts}")
            
            except Exception as e:
                print(f"Error during login: {e}")
                print("Please try again later.")
                return False

        print("\nMaximum login attempts exceeded. Application locked.")
        return False

    def get_air_quality(self, city):
        """Fetch air quality data from OpenWeather API"""
        try:
            # First, get coordinates for the city
            geo_url = f"http://api.openweathermap.org/geo/1.0/direct?q={city}&limit=1&appid={API_KEY}"
            geo_response = requests.get(geo_url)
            geo_data = geo_response.json()
            
            if not geo_data:
                print(f"City '{city}' not found.")
                return None
                
            lat = geo_data[0]['lat']
            lon = geo_data[0]['lon']
            
            # Get air quality data
            aqi_url = f"http://api.openweathermap.org/data/2.5/air_pollution?lat={lat}&lon={lon}&appid={API_KEY}"
            aqi_response = requests.get(aqi_url)
            return aqi_response.json()
            
        except Exception as e:
            print(f"Error fetching air quality data: {e}")
            return None

    def display_air_quality(self, data):
        """Display air quality information"""
        if not data:
            print("Unable to fetch air quality data.")
            return

        try:
            aqi = data['list'][0]['main']['aqi']
            components = data['list'][0]['components']

            print("\n=== Air Quality Information ===")
            print(f"Air Quality Index (AQI): {aqi}")
            
            print("\nPollutant Levels (μg/m³):")
            print(f"PM2.5: {components.get('pm2_5', 'N/A')}")
            print(f"PM10:  {components.get('pm10', 'N/A')}")
            print(f"NO2:   {components.get('no2', 'N/A')}")
            print(f"SO2:   {components.get('so2', 'N/A')}")
            print(f"O3:    {components.get('o3', 'N/A')}")
            print(f"CO:    {components.get('co', 'N/A')}")

            print("\nHealth Recommendations:")
            if aqi == 1:
                print("Air quality is Good")
                print("- Perfect for outdoor activities")
                print("- No health risks identified")
            elif aqi == 2:
                print("Air quality is Fair")
                print("- Sensitive individuals should reduce outdoor activity")
                print("- General population can continue normal activities")
            elif aqi == 3:
                print("Air quality is Moderate")
                print("- Consider wearing a mask outdoors")
                print("- Reduce prolonged outdoor activities")
            elif aqi == 4:
                print("Air quality is Poor")
                print("- Wear a mask outdoors")
                print("- Avoid prolonged outdoor activities")
                print("- Keep windows closed")
            else:
                print("Air quality is Very Poor")
                print("- Stay indoors if possible")
                print("- Wear a mask if going outside is necessary")
                print("- Keep all windows closed")
        
        except Exception as e:
            print(f"Error displaying air quality data: {e}")

    def view_history(self, email):
        """Display user's search history"""
        print("\n=== Search History ===")
        try:
            found = False
            with open(HISTORY_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if row[1] == email:
                        found = True
                        print(f"Time: {row[0]}")
                        print(f"Action: {row[2]}")
                        print(f"Details: {row[3]}")
                        print("-" * 50)
            
            if not found:
                print("No search history found.")
        
        except Exception as e:
            print(f"Error accessing history: {e}")
            print("Please try again later.")

    def main_menu(self, email):
        """Display and handle main menu options after login"""
        while True:
            print("\n=== Air Quality Monitor Main Menu ===")
            print("1. Check air quality")
            print("2. View search history")
            print("3. Logout")
            
            choice = input("\nEnter your choice (1-3): ").strip()

            if choice == '1':
                city = input("\nEnter city name: ").strip()
                data = self.get_air_quality(city)
                if data:
                    self.display_air_quality(data)
                    self.log_activity(email, "SEARCH", f"Searched air quality for {city}")
            
            elif choice == '2':
                self.view_history(email)
            
            elif choice == '3':
                self.log_activity(email, "LOGOUT", "User logged out")
                print("\nLogged out successfully!")
                break
            
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

    def run(self):
        """Main application loop"""
        try:
            while True:
                print("\n=== Welcome to Air Quality Monitoring System ===")
                print("1. Login")
                print("2. Register")
                print("3. Exit")
                
                choice = input("\nEnter your choice (1-3): ").strip()

                if choice == '1':
                    email = self.login()
                    if email:
                        self.main_menu(email)
                
                elif choice == '2':
                    self.register_user()
                
                elif choice == '3':
                    print("\nThank you for using Air Quality Monitoring System. Goodbye!")
                    break
                
                else:
                    print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nProgram terminated by user.")
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
            print("Please restart the application.")
        finally:
            print("\nExiting the application...")

def setup_api_key():
    """Setup API key if not already configured"""
    global API_KEY
    if API_KEY == 'your_openweather_api_key':
        print("\n=== OpenWeather API Setup ===")
        print("An OpenWeather API key is required to fetch air quality data.")
        print("You can get a free API key from: https://openweathermap.org/api")
        
        while True:
            key = input("\nPlease enter your OpenWeather API key: ").strip()
            if key:
                API_KEY = key
                break
            print("API key cannot be empty. Please try again.")
        
        print("\nAPI key configured successfully!")

def main():
    """Main entry point of the application"""
    try:
        # Setup API key if needed
        setup_api_key()
        
        # Create and run the application
        app = AirQualityMonitor()
        app.run()
    
    except Exception as e:
        print(f"\nFatal error: {e}")
        print("Please ensure all requirements are installed and try again.")

if __name__ == "__main__":
    main()