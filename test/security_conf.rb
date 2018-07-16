class TestSecurityConfig < Minitest::Test
  def setup
    @secconf = TinyDTLS::SecurityConfig.new
  end

  def test_add_client_and_get_key
    @secconf.add_client("foo", "bar")

    assert_equal "bar", @secconf.get_key("foo")
  end

  def test_add_nil
    assert_raises TypeError do
      @secconf.add_client("käse", nil)
    end
  end

  def test_defaults_unspecified
    @secconf.add_client("foo", "bar")
    @secconf.add_client("123", "456")
    @secconf.add_client("bar", "baz")
    @secconf.add_client("lol", "toll")
    @secconf.add_client("random", "stuff")

    assert_equal "foo", @secconf.default_id
    assert_equal "bar", @secconf.default_key
  end

  def test_defaults_specified
    @secconf.add_client("foo", "bar")
    @secconf.add_client("bar", "baz")

    @secconf.default_id = "bar"
    @secconf.default_key = "baz"

    assert_equal "bar", @secconf.default_id
    assert_equal "baz", @secconf.default_key
  end

  def test_default_id_invalid
    @secconf.add_client("123", "456")

    assert_raises TypeError do
      @secconf.default_id = "456"
    end
  end

  def test_default_key_invalid
    @secconf.add_client("123", "456")

    assert_raises TypeError do
      @secconf.default_key = "123"
    end
  end

  def test_default_id_on_empty_store
    assert_raises TypeError do
      @secconf.default_id
    end
  end

  def test_default_key_on_empty_store
    assert_raises TypeError do
      @secconf.default_key
    end
  end
end
