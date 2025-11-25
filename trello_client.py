import requests

class TrelloClient:
    def __init__(self, api_key, token):
        self.api_key = api_key
        self.token = token
        self.base_url = "https://api.trello.com/1"
        self.auth_params = {
            'key': self.api_key,
            'token': self.token
        }

    def search_cards(self, query):
        url = f"{self.base_url}/search"
        params = {
            'query': query,
            'modelTypes': 'cards',
            'card_fields': 'name,id',
            **self.auth_params
        }
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json().get('cards', [])
        except requests.exceptions.RequestException as e:
            print(f"Error searching cards: {e}")
            return []

    def get_card_attachments(self, card_id):
        url = f"{self.base_url}/cards/{card_id}/attachments"
        try:
            response = requests.get(url, params=self.auth_params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting attachments: {e}")
            return []
