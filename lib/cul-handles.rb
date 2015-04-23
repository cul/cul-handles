require 'socket'
require 'digest/sha1'
module Cul
	module Handles
		autoload :AddValueRequest, 'cul/handles/add_value_request'
		autoload :BaseMessage, 'cul/handles/base_message'
		autoload :BaseRequest, 'cul/handles/base_request'
		autoload :BaseResponse, 'cul/handles/base_response'
		autoload :ChallengeAnswerRequest, 'cul/handles/challenge_answer_request'
		autoload :ChallengeResponse, 'cul/handles/challenge_response'
		autoload :Client, 'cul/handles/client'
		autoload :CreateHandleRequest, 'cul/handles/create_handle_request'
		autoload :DH, 'cul/handles/dh'
		autoload :DeleteHandleRequest, 'cul/handles/delete_handle_request'
		autoload :DeleteValueRequest, 'cul/handles/delete_value_request'
		autoload :HandleValue, 'cul/handles/handle_value'
		autoload :HandleValueRequest, 'cul/handles/handle_value_request'
		autoload :Hdl, 'cul/handles/hdl'
		autoload :ModifyValueRequest, 'cul/handles/modify_value_request'
		autoload :ResolutionRequest, 'cul/handles/resolution_request'
		autoload :ResolutionResponse, 'cul/handles/resolution_response'
		autoload :SessionSetupRequest, 'cul/handles/session_setup_request'
		autoload :SessionSetupResponse, 'cul/handles/session_setup_response'
		autoload :SetValueRequest, 'cul/handles/set_value_request'
	end
end