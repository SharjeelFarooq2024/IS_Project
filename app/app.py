from app import create_app, db

app = create_app()


@app.cli.command("init-db")
def init_db_command():
    """Initialise the database tables."""
    with app.app_context():
        db.create_all()
    print("Database initialised.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)