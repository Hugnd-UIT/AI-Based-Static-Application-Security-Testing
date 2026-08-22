require 'sinatra'
require_relative 'controllers/main_controller'

set :port, 4567

# Entry point initializes the routes
MainController.setup(self)
