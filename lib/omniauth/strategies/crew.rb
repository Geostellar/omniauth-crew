require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Crew < OmniAuth::Strategies::OAuth2
      option :client_options,
        site: 'https://crew.com',
        authorize_url: '/oauth2/auth',
        token_url: '/oauth2/token'

      uid { raw_info['id'] }

      info do
        prune!({
          'email' => raw_info['email'],
          'first_name' => raw_info['first_name'],
          'last_name' => raw_info['last_name'],
          'phone_number' => raw_info['phone_number'],
          'referral_id' => raw_info['referral_id']
        })
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        prun! hash
      end

      def raw_info
        @raw_info ||= access_token.get('me', info_options).parsed || {}
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end
    end
  end
end
