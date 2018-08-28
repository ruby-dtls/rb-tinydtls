class TestQueue < Minitest::Test
  def setup
    @queue = TinyDTLS::Queue.new
  end

  def test_enqueue_and_dequeue
    testobj = "foobar"

    @queue.enqueue(testobj)
    assert_equal testobj, @queue.dequeue
  end

  def test_dequeue_non_blocking
    testobj = "erdbeerkäse"

    @queue.enqueue(testobj)
    assert_equal testobj, @queue.dequeue(true)
  end

  def test_enqueue_multiple
    testobjs = [
      "foo",
      "bar",
      "baz",
      12345,
    ]

    testobjs.each do |testobj|
      @queue.enqueue(testobj)
    end

    testobjs.each do |testobj|
      assert_equal testobj, @queue.dequeue
    end
  end

  def test_dequeue_empty_blocking
    testobj = 42

    thread = Thread.new do
      sleep 5
      @queue.enqueue testobj
    end

    assert_equal testobj, @queue.dequeue
  end

  def test_dequeue_empty_non_blocking
    assert_raises ThreadError do
      @queue.dequeue(true)
    end
  end
end
