import os

from backend.app import app
from backend.extensions import bcrypt
from backend.models import User, db


def migrate_data():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            print("Creating admin user...")
            password = os.environ.get("ADMIN_PASSWORD", "admin123")
            password_hash = bcrypt.generate_password_hash(
                password).decode("utf-8")
            admin = User(username="admin",
                         password_hash=password_hash, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print(f"Admin user created with ID {admin.id}")
        else:
            print("Admin user already exists.")

        # Transition existing Tabs that don't have a user_id (if any survived)
        # Actually, in the new schema user_id is NOT NULL, so they couldn't
        # have been created unless by the migration which might have left
        # them empty or failed.

        # In a real transition, we would have done this DURING the migration
        # or before making the column NOT NULL.

        print("Data transition completed.")


if __name__ == "__main__":
    migrate_data()
