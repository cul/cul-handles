module Cul
  module Handles
    class Client
      include Hdl
      DEFAULT_ADMIN = "10022/ADMIN"
      def initialize(server,port,admin=DEFAULT_ADMIN)
        @server = server
        @port = port
        @admin = admin
        @debug = false
      end
      def debug=(val)
        if(val)
          @debug = true
        else
          @debug = false
        end
      end
      def initRequest(request)
        now = Time.new
        request.requestId= now.to_i
        request.expirationTime=(Time.new().to_i + 600) # 10 minutes
        return request
      end
      def resolve(handle)
        sock = TCPSocket.new(@server,@port)
        req = ResolutionRequest.new(handle)
        req.publicOnly=true
        req.authoritative=true
        req.keepAlive=false
        req.siteInfoSerial=-1
        req.sequenceNumber=1
        now = Time.new
        req.requestId=((now.to_i * 1000000) + (now.usec % 1000))
        req.expirationTime=0
        req.sessionId= 0 #get new res.sessionId
        res = ResolutionResponse.new()
        res.send(req,sock)
        if (@debug)
          puts "Resolution Request sent"
          puts("used sessionId: " + res.sessionId.to_s + "; requestId: " + res.requestId.to_s)
          puts("response code: " + res.responseCode.to_s)
        end
        sock.close()
        return res
      end
      def createHandle(adminSecret,handle,url=nil)
        req = Cul::Handles::CreateHandleRequest.new(handle)
        initRequest(req)
        req.addAdminValue(@admin, PERM_ALL, 100)
        if not url.nil?
          req.addURLValue(url)
        end
        return sendAuthRequest(req, adminSecret)
      end
      def createAdminHandle(adminSecret, newHandle, newHandleSecret)
        req = Cul::Handles::CreateHandleRequest.new(newHandle)
        initRequest(req)
        req.addAdminValue(DEFAULT_ADMIN, PERM_ALL, 100)
        req.addSecretKeyValue(newHandleSecret)
        return sendAuthRequest(req, adminSecret)
      end
      def deleteHandle(adminSecret,handle)
        req = Cul::Handles::DeleteHandleRequest.new(handle)
        initRequest(req)
        return sendAuthRequest(req, adminSecret)
      end
      def addHandleValue(adminSecret,handle,url)
        req = Cul::Handles::AddValueRequest.new(handle)
        req.addURLValue(url)
        initRequest(req)
        return sendAuthRequest(req, adminSecret)
      end
      def changeHandleValue(adminSecret, handle, url)
        req = Cul::Handles::ModifyValueRequest.new(handle)
        req.addURLValue(url)
        initRequest(req)
        return sendAuthRequest(req, adminSecret)
      end
      def addHandleMaintainer(adminSecret,handle,maintainerHandle)
        req = Cul::Handles::AddValueRequest.new(handle)
        req.addAdminValue(maintainerHandle, 0x0070, INDEX_MAINTAINER_HANDLE)    
        initRequest(req)
        return sendAuthRequest(req, adminSecret)
      end
      def deleteHandleValue(adminSecret, handle, url)
        req = Cul::Handles::DeleteValueRequest.new(handle)
        req.addURLValue(url)
        initRequest(req)
        return sendAuthRequest(req, adminSecret)
      end
      def sendAuthRequest(request, adminSecret)
        res = ChallengeResponse.new()
        sock = TCPSocket.new(@server,@port)
        res.send(request, sock)
        sock.close()
        if not (res.responseCode.eql?RC_AUTHEN_NEEDED)
          raise "Unexpected server challenge rcode:  " + res.responseCode.to_s
        end
        creq = ChallengeAnswerRequest.new(res.nonce,res.digest,@admin,INDEX_AUTH)
        creq.sessionId = res.sessionId
        initRequest(creq)
        creq.requestId= request.requestId + 1
        creq.secret=(adminSecret)
        cres = BaseResponse.new()
        sock = TCPSocket.new(@server,@port)
        cres.send(creq, sock)
        sock.close()
        return cres        
      end
    end
  end
end