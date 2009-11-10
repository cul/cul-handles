module Cul
  module Handles
    class BaseMessage
      include Hdl
      def initialize
        @SHA1 = Digest::SHA1.new()
        @MD5 = Digest::MD5.new()
        @digest = [nil,@MD5,@SHA1]
        @majorVersion = 2 # default
        @minorVersion = 1 # default
        @digestAlg = 2 # SHA1 = 2, MD5 = 1
        @digestLength = 20 # SHA1 = 20 octets, MD5 = 16
        @sequenceNumber = [0,0,0,0]

      end
  
      def authoritative=(val)
        if(val)
          @opFlag[MSG_FLAG_AUTH_INDEX] |= MSG_FLAG_AUTH
        else
          @opFlag[MSG_FLAG_AUTH_INDEX] &= ~MSG_FLAG_AUTH
        end
      end
      def authoritative()
        return @opFlag[MSG_FLAG_AUTH_INDEX] & MSG_FLAG_AUTH > 0
      end
      def certify=(val)
        if(val)
          @opFlag[MSG_FLAG_CERT_INDEX] |= MSG_FLAG_CERT
        else
        @opFlag[MSG_FLAG_CERT_INDEX] &= ~MSG_FLAG_CERT
        end
      end
      def certify()
        return @opFlag[MSG_FLAG_CERT_INDEX] & MSG_FLAG_CERT > 0
      end
      def encrypt=(val)
        if(val)
          @opFlag[MSG_FLAG_ENCR_INDEX] |= MSG_FLAG_ENCR
        else
          @opFlag[MSG_FLAG_ENCR_INDEX] &= ~MSG_FLAG_ENCR
        end
      end
      def encrypt()
        return @opFlag[MSG_FLAG_ENCR_INDEX] & MSG_FLAG_ENCR > 0
      end
      def recursive=(val)
        if(val)
          @opFlag[MSG_FLAG_RECU_INDEX] |= MSG_FLAG_RECU
        else
          @opFlag[MSG_FLAG_RECU_INDEX] &= ~MSG_FLAG_RECU
        end
      end
      def recursive()
        return @opFlag[MSG_FLAG_RECU_INDEX] & MSG_FLAG_RECU > 0
      end
      def cacheCertify=(val)
        if(val)
          @opFlag[MSG_FLAG_CACR_INDEX] |= MSG_FLAG_CACR
        else
          @opFlag[MSG_FLAG_CACR_INDEX] &= ~MSG_FLAG_CACR
        end
      end
      def cacheCertify()
        return @opFlag[MSG_FLAG_CACR_INDEX] & MSG_FLAG_CACR > 0
      end
      def continuous=(val)
        if(val)
          @opFlag[MSG_FLAG_CONT_INDEX] |= MSG_FLAG_CONT
        else
        @opFlag[MSG_FLAG_CONT_INDEX] &= ~MSG_FLAG_CONT
        end
      end
      def continuous()
        return @opFlag[MSG_FLAG_CONT_INDEX] & MSG_FLAG_CONT > 0
      end
      def keepAlive=(val)
        if(val)
          @opFlag[MSG_FLAG_KPAL_INDEX] |= MSG_FLAG_KPAL
        else
          @opFlag[MSG_FLAG_KPAL_INDEX] &= ~MSG_FLAG_KPAL
        end
      end
      def keepAlive()
        return @opFlag[MSG_FLAG_KPAL_INDEX] & MSG_FLAG_KPAL > 0
      end
      def publicOnly=(val)
        if(val)
          @opFlag[MSG_FLAG_PUBL_INDEX] |= MSG_FLAG_PUBL
        else
        @opFlag[MSG_FLAG_PUBL_INDEX] &= ~MSG_FLAG_PUBL
        end
      end
      def publicOnly()
        return @opFlag[MSG_FLAG_PUBL_INDEX] & MSG_FLAG_PUBL > 0
      end
      def returnRequestDigest=(val)
        if(val)
          @opFlag[MSG_FLAG_RRDG_INDEX] |= MSG_FLAG_RRDG
        else
          @opFlag[MSG_FLAG_RRDG_INDEX] &= ~MSG_FLAG_RRDG
        end
      end
      def returnRequestDigest()
        return @opFlag[MSG_FLAG_RRDG_INDEX] & MSG_FLAG_RRDG > 0
      end
      def digestAlg=(val)
        if(val == 1)
          @digest = @MD5
          @digestLength = 16
        elsif(val == 2)
          @digest = @SHA1
          @digestLength = 20
        else
          @digest = nil      
          @digestLength = 0
        end
      end
    end
  end
end