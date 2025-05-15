import math
import json
import hashlib
import time
from typing import Set, Tuple


class HyperLogLog:
    def __init__(self, b: int = 14):
        """
        b — кількість бітів (кількість регістрів = 2^b). Зазвичай 12–16.
        """
        self.b = b
        self.m = 1 << b
        self.alpha_mm = self._get_alpha_mm()
        self.registers = [0] * self.m

    def _get_alpha_mm(self):
        if self.m == 16:
            return 0.673 * self.m * self.m
        elif self.m == 32:
            return 0.697 * self.m * self.m
        elif self.m == 64:
            return 0.709 * self.m * self.m
        else:
            return (0.7213 / (1 + 1.079 / self.m)) * self.m * self.m

    def _hash(self, value: str) -> int:
        return int(hashlib.sha1(value.encode()).hexdigest(), 16)

    def add(self, value: str):
        x = self._hash(value)
        j = x & (self.m - 1)        # індекс
        w = x >> self.b             # залишок
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w: int) -> int:
        return (w.bit_length() - w.bit_length() + 1) if w == 0 else (w.bit_length() - w.bit_length() + 1)

    def count(self) -> int:
        Z = 1.0 / sum(2.0 ** -r for r in self.registers)
        E = self.alpha_mm * Z

        if E <= 2.5 * self.m:
            V = self.registers.count(0)
            if V != 0:
                E = self.m * math.log(self.m / V)
        elif E > (1 / 30.0) * (1 << 32):
            E = -(1 << 32) * math.log(1 - E / (1 << 32))
        return int(E)


def load_log_lines(file_path: str):
    """
    Генератор, який читає великий лог-файл построково.
    Ігнорує невалідні JSON рядки.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                yield json.loads(line.strip())
            except json.JSONDecodeError:
                continue


def count_unique_ips_set(log_iterable) -> Tuple[int, float]:
    """
    Точний підрахунок унікальних IP за допомогою set.
    """
    unique_ips: Set[str] = set()
    start = time.time()
    for entry in log_iterable:
        ip = entry.get("remote_addr")
        if ip:
            unique_ips.add(ip)
    return len(unique_ips), time.time() - start


def count_unique_ips_hll(log_iterable) -> Tuple[int, float]:
    """
    Приблизний підрахунок унікальних IP за допомогою HyperLogLog.
    """
    hll = HyperLogLog()
    start = time.time()
    for entry in log_iterable:
        ip = entry.get("remote_addr")
        if ip:
            hll.add(ip)
    return hll.count(), time.time() - start


def compare_methods(file_path: str):
    print(f"Обробка файлу: {file_path}\n")

    # Два генератори — один для set, інший для HyperLogLog
    log1 = load_log_lines(file_path)
    exact_count, exact_time = count_unique_ips_set(log1)

    log2 = load_log_lines(file_path)
    approx_count, approx_time = count_unique_ips_hll(log2)

    print("Результати порівняння:")
    print(f"{'':<30}{'Точний підрахунок':<20}{'HyperLogLog':<15}")
    print(f"{'Унікальні елементи':<30}{exact_count:<20}{approx_count:<15}")
    print(f"{'Час виконання (сек.)':<30}{exact_time:.5f}{' ' * 9}{approx_time:.5f}")


if __name__ == "__main__":
    compare_methods("/Users/kraven/Documents/GitHub/goit-algo2-hw-05/task02/access.log")
