from app_main import app
import auth  # Import auth module (includes LoginManager setup)
import routes  # Import routes module

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
