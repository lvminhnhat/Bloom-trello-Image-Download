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
        all_cards = []
        page = 0
        limit = 1000
        
        while True:
            params = {
                'query': query,
                'modelTypes': 'cards',
                'card_fields': 'name,id',
                'cards_limit': limit,
                'cards_page': page,
                **self.auth_params
            }
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                cards = data.get('cards', [])
                
                if not cards:
                    break
                    
                all_cards.extend(cards)
                page += 1
                
                # If we got fewer cards than the limit, we've reached the end
                if len(cards) < limit:
                    break
                    
            except requests.exceptions.RequestException as e:
                print(f"Error searching cards: {e}")
                break
                
        return all_cards

    def get_card_attachments(self, card_id):
        url = f"{self.base_url}/cards/{card_id}/attachments"
        try:
            response = requests.get(url, params=self.auth_params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting attachments: {e}")
            return []
