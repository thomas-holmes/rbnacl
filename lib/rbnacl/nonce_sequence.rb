class Crypto
  # Generates monotonically increasing nonces
  #
  # With both the Box and SecretBox classes it is essential that a nonce is
  # **never** reused.  To do so compromises the confidentiality and integrity of
  # the system.  While a random nonce of 24-bytes is statistically unique, a
  # carefully managed monotonic nonce is provably unique, and also offers useful
  # properties such as resistance to replay attacks.
  class NonceSequence
    attr_accessor :prefix

    # Create a new Nonce sequence
    #
    # @param prefix [String] The prefix for the nonce. 16 bytes long
    # @param count [Integer] The initial value for the counter
    # @param max    [Integer] The maximum counter value that can be used.
    def initialize(prefix, start=1, max=2**64-1)
      @prefix = prefix
      @count  = start
      @max    = max
    end

    # returns the current count of the nonce
    #
    # @param unsafe [Boolean, Symbol] if passed ':unsafe', doesn't increment the nonce before returning
    #
    # @return [Integer] The current counter
    def to_i(unsafe = false)
      unsafe == :unsafe ? @count : increment_counter
    end

    # returns the next value in the nonce sequence
    #
    # @return [CounterNonce] The new nonce, which responds to #to_s
    def next
      CounterNonce.new(prefix, increment_counter)
    end

    private

    # next counter value
    #
    # This is provided mostly as a convenience for subclasses.  It allows the
    # nonce increment function to be decoupled from some sanity checks around
    # the value, such as checking for overflow.
    def next_counter_value
      @count + 1
    end

    # Increments the counter
    #
    # increments the counter by calling #next_counter_value.  It has sanity
    # checks for ensuring that a counter is indeed incremented.  Also, it checks
    # for overflow.
    #
    # @raise [CounterOverflowError] if the counter is too large.
    def increment_counter
      new_count = next_counter_value
      if new_count <= @count
        @count = @count + 1
      else
        @count = new_count
      end
      check_overflow
      @count
    end

    def check_overflow
      raise CounterOverflowError, "Counter max is #{@max}", caller if @count >= @max
    end
  end

  # Time nonce sequence using the micro-second resolution timer
  #
  # Otherwise, just a counter.  This means you can be a little more relaxed
  # about keeping track of the counter, though you still have to be careful
  # about clocks moving backwards.
  class TimeNonceSequence
    def initialize(prefix, count=next_counter_value, max=2**64-1)
      super
    end

    private
    def next_counter_value
      (Time.now.to_f*1000000).to_i
    end
  end
end
