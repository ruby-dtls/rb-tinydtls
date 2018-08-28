module TinyDTLS
  # This class implements a concurrent queue using semaphores.
  #
  # The concurrent queue implementation from the standard library cannot
  # be used since it doesn't over a peek operation. This operation is
  # required to implement the `MSG_PEEK` flag.
  #
  # The implementation is briefly modeled after the two-lock algorithm
  # introduced in [this paper](https://dl.acm.org/citation.cfm?id=248106).
  class Queue
    class Node < Struct.new(:value, :next); end

    # Creates a new instance of the queue.
    def initialize
      @tail_lock = Mutex.new
      @head_lock = Mutex.new

      node  = Node.new
      @head = node
      @tail = node

      @sema = Concurrent::Semaphore.new(0)
    end

    # Adds a new obj to the queue.
    def enqueue(obj)
      node = Node.new(obj)

      @tail_lock.synchronize do
        @tail.next = node
        @tail = node
      end

      @sema.release
    end

    # Retrieves data from the queue. If the queue is empty, the calling
    # thread is suspended until data is pushed onto the queue. If
    # `non_block` is true, the thread isn't suspended, and an exception
    # is raised.
    def dequeue(non_block = false)
      acquire(non_block)

      @head_lock.synchronize do
        new_head = @head.next

        value = new_head.value
        @head = new_head

        value
      end
    end

    # Fetches an object at the head of queue, without removing it. If
    # the queue is empty, the calling thread is suspended until data is
    # pushed onto the queue. If `non_block` is true, the thread isn't
    # suspended, and an exception is raised.
    def peek(non_block = false)
      acquire(non_block)

      value = @head_lock.synchronize { @head.next.value }
      @sema.release

      value
    end

    private

    def acquire(non_block)
      if non_block
        raise ThreadError unless @sema.try_acquire
      else
        @sema.acquire
      end
    end
  end
end
