module Cul
  module Handles
    class DH
      include Hdl
      attr_reader :prime, :generator, :maxrand, :publickey
    #  def DH.miller_rabin(a, n)
    #    
    #  end
    #  def DH.prime
    #    
    #  end
      def DH.mod_exp start, e, m
        result = 1
        b = start
        while e > 0
          result = (result * b) % m if e[0] == 1
          e = e >> 1
          b = (b*b) %m
        end
        return result
      end
      def initialize(prime, generator, maxrand)
        @prime = prime
        @generator = generator
        @maxrand = maxrand
        @publickey = 0 #public key
        @key = 0 #shared secret
        @private = 0 #private key
      end
      def generate tries=16 # shared key
        tries.times do
          @private = rand(@maxrand)
          @publickey = DH.mod_exp(@generator, @private, @prime)
          return @publickey if self.valid?
        end
      end
      def secret f # private key
        @key = DH.mod_exp(f,@private,@prime)
        @key
      end
      def valid? _e = self.publickey
        _e and _e.between?(2,self.prime-2) and _e != 0
      end
      def encodeKeyParms
        result = []
        publicBytes = asBytes(@publickey)
        result.concat(asBytes(publicBytes.length))
        result.concat(publicBytes)
        primeBytes = asBytes(@prime)
        result.concat(asBytes(primeBytes.length))
        result.concat(primeBytes)
        genBytes = asBytes(@generator)
        result.concat(asBytes(genBytes.length))
        result.concat(genBytes)
        result
      end
    end
  end
end