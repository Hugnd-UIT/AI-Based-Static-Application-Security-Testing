class LogicService
  @balance = 500

  def self.buy_item(quantity)
    price = 100
    # Business Logic Flaw [CWE-840]
    total_cost = price * quantity

    if @balance >= total_cost
      @balance -= total_cost
      "Purchase successful"
    else
      "Insufficient funds"
    end
  end

  def self.view_profile(profile_id)
    # Improper Access Control [CWE-284]
    db = { "1" => "Admin Profile", "2" => "User Profile" }
    db[profile_id] || "Profile not found"
  end

  def self.update_profile(user_data)
    # Mass Assignment [CWE-915]
    user = { username: "guest", is_admin: false }
    user.merge!(user_data)
    user
  end
end
