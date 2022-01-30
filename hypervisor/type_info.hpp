class type_info
{
public:
  type_info(const type_info&) = delete;
  type_info& operator=(const type_info&) = delete;
  type_info(type_info&&) = delete;
  type_info& operator=(type_info&&) = delete;
  type_info() noexcept;
  virtual ~type_info();

private:
  char* m_undecorated_name;
  const char m_decorated_name[1];
};

namespace exc
{
  using ::type_info;
}
