import math
import hashlib


class BloomFilter:
    def __init__(self, expected_items=100000, false_positive_rate=0.01):
        self.size = self._get_size(expected_items, false_positive_rate)
        self.hash_count = self._get_hash_count(self.size, expected_items)
        self.bit_array = bytearray((self.size + 7) // 8)  # байтова мапа

    def _get_size(self, n, p):
        return int(-(n * math.log(p)) / (math.log(2) ** 2))

    def _get_hash_count(self, m, n):
        return int((m / n) * math.log(2))

    def _hashes(self, item):
        item_bytes = str(item).encode("utf-8")
        h1 = int(hashlib.md5(item_bytes).hexdigest(), 16)
        h2 = int(hashlib.sha1(item_bytes).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def _set_bit(self, bit_index):
        byte_index = bit_index // 8
        bit_position = bit_index % 8
        self.bit_array[byte_index] |= 1 << bit_position

    def _get_bit(self, bit_index):
        byte_index = bit_index // 8
        bit_position = bit_index % 8
        return (self.bit_array[byte_index] >> bit_position) & 1

    def add(self, item):
        for hash_val in self._hashes(item):
            self._set_bit(hash_val)

    def __contains__(self, item):
        return all(self._get_bit(hash_val) for hash_val in self._hashes(item))


def check_password_uniqueness(password_list, bloom_filter):
    check_results = []

    for password_str in password_list:
        if not isinstance(password_str, str) or not password_str.strip():
            check_results.append(False)
            continue

        if password_str in bloom_filter:
            check_results.append(False)
        else:
            bloom_filter.add(password_str)
            check_results.append(True)

    return check_results


if __name__ == "__main__":
    test_password_list = [
        "password123", "123456", "helloWorld", "123456", "password123",
        "", None, "   ", "newPass"
    ]

    bloom = BloomFilter(expected_items=1000)
    results = check_password_uniqueness(test_password_list, bloom)

    for pw, is_unique in zip(test_password_list, results):
        print(f"'{pw}' -> {'Унікальний' if is_unique else 'Вже використовувався або некоректний'}")
