import requests
import xmltodict


class CASClient:
    SSO_URL = "https://sso.ui.ac.id/cas2"

    def __init__(self, service_url: str):
        self.service_url = service_url
        self.login_url = f"{self.SSO_URL}/login?service={service_url}"
        self.auth_url = f"{self.SSO_URL}/serviceValidate?service={service_url}&ticket="

    def authenticate(self, ticket: str):
        request_url = self.auth_url + ticket
        res = requests.get(
            request_url,
            headers={
                "Host": "sso.ui.ac.id",
                "User-Agent": "PyRequest",
            },
        )
        res.raise_for_status()

        parsed = xmltodict.parse(
            res.text,
            process_namespaces=True,
            namespaces={
                "http://www.yale.edu/tp/cas": None,
            },
        )
        return parsed
