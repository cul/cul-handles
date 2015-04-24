# -*- encoding: utf-8 -*-
require 'test_helper'
module Cul
  module Handles
    class DHTest < Test::Unit::TestCase
      def testDHKeys()
        maxrand = (2**513) - 1
        alice = DH.new(53, 5,maxrand)
        bob = DH.new(53, 5, maxrand)
        alice.generate
        assert(alice.valid?)
        bob.generate
        assert(bob.valid?)
        assert(alice.publickey != bob.publickey)
        assert(alice.secret(bob.publickey) == bob.secret(alice.publickey))
      end
    end
  end
end