template <typename T>
T shared_template(T a, T b) {
  return a + b;
}

using Fn = int (*)(int, int);

int from_a() { return shared_template(10, 20); }
Fn address_from_a() { return &shared_template<int>; }
