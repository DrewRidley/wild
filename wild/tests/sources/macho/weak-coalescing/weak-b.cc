template <typename T>
T shared_template(T a, T b) {
  return a + b;
}

using Fn = int (*)(int, int);

int from_b() { return shared_template(30, 40); }
Fn address_from_b() { return &shared_template<int>; }
