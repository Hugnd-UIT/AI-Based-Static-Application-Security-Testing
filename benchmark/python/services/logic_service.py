balance = 500

def buy_item(quantity):
    global balance
    price = 100
    
    # Business Logic Flaw (Negative Quantity) [CWE-840]
    total_cost = price * quantity
    
    if balance >= total_cost:
        balance -= total_cost
        return f"Purchase successful! New balance: {balance}"
    else:
        return "Insufficient funds."

def view_profile(profile_id):
    # Improper Access Control / IDOR [CWE-284]
    db = { "1": "Admin Profile", "2": "User Profile" }
    
    if profile_id in db:
        return db[profile_id]
    else:
        return "Profile not found"
