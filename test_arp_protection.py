#!/usr/bin/env python
import pytest
import subprocess
import time
from unittest.mock import patch, MagicMock
import scapy.all as scapy
import platform
from io import StringIO
import sys
import os
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from arp_protection import (get_arguments, get_mac, validate_arp_packet,
                          process_sniffed_packet, disable_network,
                          restore_network, get_platform)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='test_arp_protection.log'
)

test_logger = logging.getLogger(__name__)
StopIteration
# Тестовые данные
TEST_INTERFACE = "eth0"
TEST_IP = "192.168.1.0"
TEST_LINUX = "Linux"
TEST_WINDOWS = "Windows"
TEST_MAC = "e8:2a:44:23:81:30"
FAKE_MAC = "aa:bb:cc:dd:ee:ff"

def print_test_header(test_name):
    """Печатает заголовок теста"""
    test_logger.info("="*60)
    test_logger.info(f"ТЕСТ: {test_name}")
    test_logger.info("="*60)

def print_test_step(step):
    """Печатает шаг теста"""
    test_logger.info(f">>> {step}")

### Модульные тесты

def test_get_arguments(monkeypatch):
    print_test_header("Парсинг аргументов командной строки")
    print_test_step("Создаем тестовые аргументы: -i eth0")
    
    test_args = ["-i", TEST_INTERFACE]
    with patch.object(sys, 'argv', ["arp_protection.py"] + test_args):
        args = get_arguments()
        assert args.interface == TEST_INTERFACE
        test_logger.info("[OK] Интерфейс корректно распознан")

def test_get_mac(monkeypatch):
    print_test_header("Получение MAC адреса по IP")
    print_test_step(f"Мокаем ответ ARP для IP {TEST_IP} с MAC {TEST_MAC}")
    
    mock_received = MagicMock()
    mock_received.hwsrc = TEST_MAC
    mock_packet = MagicMock()
    mock_packet.__getitem__.return_value = mock_received
    
    monkeypatch.setattr(
        scapy, 'srp',
        lambda *args, **kwargs: ([(None, mock_packet)], None)
    )
    
    mac = get_mac(TEST_IP)
    assert mac == TEST_MAC
    test_logger.info(f"[OK] Получен корректный MAC: {mac}")

def test_validate_arp_packet():
    print_test_header("Валидация ARP пакетов")
    
    # Тест валидного ARP ответа
    print_test_step("Создаем валидный ARP ответ")
    valid_packet = scapy.ARP(op=2, psrc="192.168.1.1", hwsrc=TEST_MAC)
    assert validate_arp_packet(valid_packet) is True
    test_logger.info("[OK] Валидный пакет распознан")
    
    # Тест невалидного ARP запроса
    print_test_step("Создаем невалидный ARP запрос")
    invalid_packet = scapy.ARP(op=1)
    assert validate_arp_packet(invalid_packet) is False
    test_logger.info("[OK] Невалидный пакет отфильтрован")

### Интеграционные тесты
@pytest.fixture
def mock_platform(monkeypatch):
    monkeypatch.setattr(platform, 'system', lambda: "Linux")
    monkeypatch.setattr('arp_protection.INTERFACE', TEST_INTERFACE)
    monkeypatch.setattr('arp_protection.OS_NAME', "Linux")

def test_process_sniffed_packet_attack(mock_platform, monkeypatch, capsys):
    print_test_header("Обнаружение ARP Spoofing атаки")
    print_test_step(f"Симулируем атаку: IP {TEST_IP} подменяет MAC {TEST_MAC} на {FAKE_MAC}")
    
    monkeypatch.setattr(
        'arp_protection.get_mac',
        lambda ip: TEST_MAC if ip == TEST_IP else None
    )
    
    monkeypatch.setattr(
        'arp_protection.disable_network',
        lambda: print(">>> [ЗАЩИТА] Отключаем сетевой интерфейс!")
    )
    
    attack_packet = scapy.ARP(
        op=2,
        psrc=TEST_IP,
        hwsrc=FAKE_MAC,
        pdst="192.168.1.2"
    )
    
    process_sniffed_packet(attack_packet)
    
    captured = capsys.readouterr()
    assert "WARNING: ARP Spoofing Attack Detected!" in captured.out
    test_logger.info("[OK] Атака успешно обнаружена")
    test_logger.info("[OK] Защитный механизм активирован")

def test_process_sniffed_packet_normal(mock_platform, monkeypatch, capsys):
    print_test_header("Обработка нормального ARP трафика")
    print_test_step(f"Создаем нормальный ARP ответ от {TEST_IP} (MAC: {TEST_MAC})")
    
    monkeypatch.setattr(
        'arp_protection.get_mac',
        lambda ip: TEST_MAC if ip == TEST_IP else None
    )
    
    normal_packet = scapy.ARP(
        op=2,
        psrc=TEST_IP,
        hwsrc=TEST_MAC,
        pdst="192.168.1.2"
    )
    
    process_sniffed_packet(normal_packet)
    
    captured = capsys.readouterr()
    assert "WARNING:" not in captured.out
    test_logger.info("[OK] Нормальный трафик не вызывает ложных срабатываний")

### Тест симуляции ARP poisoning
def test_arp_poisoning_simulation(mock_platform, monkeypatch, capsys):
    print_test_header("Симуляция комплексной ARP Poisoning атаки")
    print_test_step("Готовим 3 варианта поддельных ARP пакетов")
    
    monkeypatch.setattr(
        'arp_protection.get_mac',
        lambda ip: TEST_MAC if ip == TEST_IP else None
    )
    
    monkeypatch.setattr(
        'arp_protection.disable_network',
        lambda: print(">>> [ЗАЩИТА] Сработал механизм блокировки сети!")
    )
    
    attack_packets = [
        scapy.ARP(op=2, psrc=TEST_IP, hwsrc=FAKE_MAC, pdst="192.168.1.2"),
        scapy.ARP(op=2, psrc="192.168.1.100", hwsrc=FAKE_MAC, pdst="192.168.1.1"),
        scapy.ARP(op=2, psrc="192.168.1.1", hwsrc="00:00:00:00:00:01", pdst="192.168.1.2")
    ]
    
    for i, packet in enumerate(attack_packets, 1):
        print_test_step(f"Атака #{i}: {packet.psrc} -> {packet.pdst} (поддельный MAC: {packet.hwsrc})")
        process_sniffed_packet(packet)
        time.sleep(0.5)
    
    captured = capsys.readouterr()
    assert "WARNING: ARP Spoofing Attack Detected!" in captured.out
    test_logger.info("[OK] Все атаки успешно обнаружены")
    test_logger.info("[OK] Защитные механизмы сработали корректно")

### Тесты для функций работы с сетью
def test_disable_network_linux(mock_platform, monkeypatch):
    print_test_header("Тест отключения сети (Linux)")
    print_test_step("Мокаем вызов ip wlp3s0 down")
    
    mock_run = MagicMock()
    monkeypatch.setattr(subprocess, 'run', mock_run)

    disable_network()
    
    mock_run.assert_called_with(["ip link set dev ", TEST_INTERFACE, "down"], check=True)
    test_logger.info("[OK] Команда отключения интерфейса выполнена")

def test_restore_network_linux(mock_platform, monkeypatch):
    print_test_header("Тест восстановления сети (Linux)")
    print_test_step("Мокаем вызов ip wlp3s0 up")

    mock_run = MagicMock()
    monkeypatch.setattr(subprocess, 'run', mock_run)
    
    restore_network()
    
    mock_run.assert_called_with(["ip link set dev ", TEST_INTERFACE, "up"], check=True)
    test_logger.info("[OK] Команда включения интерфейса выполнена")

def test_disable_network_windows(monkeypatch):
    print_test_header("Тест отключения сети (Windows)")
    print_test_step("Мокаем вызов netsh для отключения интерфейса")
    
    monkeypatch.setattr(platform, 'system', lambda: "Windows")
    monkeypatch.setattr('arp_protection.INTERFACE', TEST_INTERFACE)
    monkeypatch.setattr('arp_protection.OS_NAME', TEST_WINDOWS)
    
    mock_run = MagicMock()
    monkeypatch.setattr(subprocess, 'run', mock_run)
    
    # Явно вызываем disable_network
    from arp_protection import disable_network
    disable_network()
    
    mock_run.assert_called_with(
        ["netsh", "interface", "set", "interface", TEST_INTERFACE, "disable"],
        check=True
    )
    test_logger.info("[OK] Windows команда отключения выполнена")


if __name__ == "__main__":
    pytest.main(["-v", __file__])