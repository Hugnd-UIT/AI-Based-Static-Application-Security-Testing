require_relative '../services/db_service'
require_relative '../services/file_service'
require_relative '../services/xml_service'
require_relative '../services/deserialize_service'
require_relative '../services/http_service'
require_relative '../services/crypto_service'
require_relative '../services/logic_service'
require_relative '../utils/system_util'

class MainController
  def self.setup(app)
    app.get '/user' do
      DbService.get_user(params[:id])
      "User fetched"
    end

    app.get '/ping' do
      SystemUtil.run_ping(params[:ip])
      "Ping executed"
    end

    app.get '/read' do
      FileService.read_file(params[:file])
      "File read"
    end

    app.post '/xml' do
      request.body.rewind
      XmlService.parse_xml(request.body.read)
      "XML parsed"
    end

    app.post '/deserialize' do
      request.body.rewind
      DeserializeService.load_data(request.body.read)
      "Data loaded"
    end

    app.get '/fetch' do
      HttpService.fetch_url(params[:url])
      "URL fetched"
    end

    app.get '/hash' do
      CryptoService.hash_data(params[:data])
      "Data hashed"
    end

    app.post '/buy' do
      LogicService.buy_item(params[:quantity].to_i)
      "Purchase processed"
    end

    app.get '/profile' do
      LogicService.view_profile(params[:id])
    end

    app.post '/update_profile' do
      LogicService.update_profile(params[:user_data])
      "Profile updated"
    end

    app.get '/sca' do
      payload = params[:payload] || ""
      
      # nokogiri
      require 'nokogiri'
      Nokogiri::XML(payload)
      
      # sinatra
      erb payload
      
      # rack
      require 'rack'
      Rack::Utils.parse_nested_query(payload)
      
      # loofah
      require 'loofah'
      Loofah.fragment(payload).scrub!(:strip)
      
      "SCA Executed"
    end
  end
end
