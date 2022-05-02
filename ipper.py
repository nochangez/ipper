import json
import requests
from os import popen


class NotCorrectIp(Exception):
    pass


class NetworkError(BaseException):
    pass


def is_valid(func):
    def wrapper(ip: str):
        if (len(ip.split('.')) == 4) and (len(str(ip.split('.'))[0]) <= 255) \
                and (len(str(ip.split('.'))[0]) >= 0):
            return func(ip)
        raise NotCorrectIp("ip is not correct, check it")

    return wrapper


class Collector:
    _source: str = "http://ipinfo.io/"

    @staticmethod
    @is_valid
    def get_ip_data(ip: str) -> dict:
        response = requests.get(url=f"{Collector._source}{ip}/json")

        if response.status_code == 200:
            return json.loads(response.text)
        else:
            raise NetworkError(f"status code: [{response.status_code}]\nSeems host is down or server is not available")

    @staticmethod
    @is_valid
    def get_full_ip_data(ip: str):
        whois_data = popen(f"whois {ip}").read()
        return whois_data


if __name__ == "__main__":
    collector = Collector()

    address = str(input("[-] enter an ip: "))

    ip_data = collector.get_ip_data(address)
    full_ip_data = collector.get_full_ip_data(address)

    print(f"{ip_data}\n\n\n{full_ip_data}")

