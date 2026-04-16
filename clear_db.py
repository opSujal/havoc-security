from data_manager import DatabaseManager

db = DatabaseManager('vapt_database.db')
db.clear_database()
print("Database cleared successfully.")
