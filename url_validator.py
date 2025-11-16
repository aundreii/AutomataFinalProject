class UrlDFA:
    def __init__(self):
        # Define DFA states
        self.states = {
            'start',              # Initial state
            'scheme',             # After http/https
            'scheme_separator',   # After ://
            'authority',          # Domain name part
            'path',               # After / in path
            'query',              # After ? in query
            'fragment',           # After # in fragment
            'rejected'            # Invalid state
        }
        
        # Define alphabet
        self.alphabet = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&\'()*+,;=%')
        
        # Define transition function
        self.transition_function = {}
        
        # Start state transitions - must start with http or https
        for char in self.alphabet:
            if char == 'h':
                self.transition_function[('start', char)] = 'scheme'
            else:
                self.transition_function[('start', char)] = 'rejected'
        
        # Scheme transitions (http or https)
        self.transition_function[('scheme', 't')] = 'scheme'
        self.transition_function[('scheme', 'p')] = 'scheme'
        self.transition_function[('scheme', 's')] = 'scheme'
        self.transition_function[('scheme', ':')] = 'scheme_separator'
        
        # Add transitions for other characters in scheme
        for char in self.alphabet:
            if char not in 'tps:':
                self.transition_function[('scheme', char)] = 'rejected'
        
        # Scheme separator transitions (://)
        self.transition_function[('scheme_separator', '/')] = 'scheme_separator'
        
        # After :// we should have domain name
        for char in self.alphabet:
            if char not in '/:':
                self.transition_function[('scheme_separator', char)] = 'authority'
        
        # Authority (domain) transitions
        for char in self.alphabet:
            if char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._':
                self.transition_function[('authority', char)] = 'authority'
            elif char == '/':
                self.transition_function[('authority', char)] = 'path'
            elif char == '?':
                self.transition_function[('authority', char)] = 'query'
            elif char == '#':
                self.transition_function[('authority', char)] = 'fragment'
            else:
                self.transition_function[('authority', char)] = 'rejected'
        
        # Path transitions
        for char in self.alphabet:
            if char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/@!$&\'()*+,;=%':
                self.transition_function[('path', char)] = 'path'
            elif char == '?':
                self.transition_function[('path', char)] = 'query'
            elif char == '#':
                self.transition_function[('path', char)] = 'fragment'
            else:
                self.transition_function[('path', char)] = 'rejected'
        
        # Query transitions
        for char in self.alphabet:
            if char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?@!$&\'()*+,;=%':
                self.transition_function[('query', char)] = 'query'
            elif char == '#':
                self.transition_function[('query', char)] = 'fragment'
            else:
                self.transition_function[('query', char)] = 'rejected'
        
        # Fragment transitions
        for char in self.alphabet:
            if char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?@!$&\'()*+,;=%#':
                self.transition_function[('fragment', char)] = 'fragment'
            else:
                self.transition_function[('fragment', char)] = 'rejected'
        
        # Define start state
        self.start_state = 'start'
        
        # Define accept states - URL can end at authority, path, query, or fragment
        self.accept_states = {'authority', 'path', 'query', 'fragment'}
    
    def validate_url(self, url):
        """
        Validate a URL using the DFA
        
        Parameters:
        - url: the URL to validate
        
        Returns:
        - True if the URL is valid, False otherwise
        - The sequence of states visited
        """
        current_state = self.start_state
        state_sequence = [current_state]
        
        for char in url:
            if char not in self.alphabet:
                return False, state_sequence + ['rejected']
            
            if (current_state, char) not in self.transition_function:
                return False, state_sequence + ['rejected']
            
            current_state = self.transition_function[(current_state, char)]
            state_sequence.append(current_state)
            
            if current_state == 'rejected':
                return False, state_sequence
        
        return current_state in self.accept_states, state_sequence
    
    def analyze_url_components(self, url):
        """
        Analyze and extract components of a valid URL
        
        Parameters:
        - url: the URL to analyze
        
        Returns:
        - Dictionary with URL components or None if invalid
        """
        valid, state_sequence = self.validate_url(url)
        
        if not valid:
            return None
        
        # Extract URL components
        components = {}
        
        # Find scheme (http or https)
        scheme_end = url.find('://')
        if scheme_end != -1:
            components['scheme'] = url[:scheme_end]
            url_without_scheme = url[scheme_end + 3:]
        else:
            return None  # Invalid URL format
        
        # Find authority (domain)
        path_start = url_without_scheme.find('/')
        query_start = url_without_scheme.find('?')
        fragment_start = url_without_scheme.find('#')
        
        # Determine where authority ends
        authority_end = len(url_without_scheme)
        for pos in [path_start, query_start, fragment_start]:
            if pos != -1 and pos < authority_end:
                authority_end = pos
        
        components['authority'] = url_without_scheme[:authority_end]
        
        # Extract path if present
        if path_start != -1:
            path_end = len(url_without_scheme)
            for pos in [query_start, fragment_start]:
                if pos != -1 and pos < path_end:
                    path_end = pos
            
            components['path'] = url_without_scheme[path_start:path_end]
        else:
            components['path'] = ''
        
        # Extract query if present
        if query_start != -1:
            query_end = fragment_start if fragment_start != -1 else len(url_without_scheme)
            components['query'] = url_without_scheme[query_start:query_end]
        else:
            components['query'] = ''
        
        # Extract fragment if present
        if fragment_start != -1:
            components['fragment'] = url_without_scheme[fragment_start:]
        else:
            components['fragment'] = ''
        
        return components


def main():
    print("URL Validator using DFA")
    print("======================")
    
    url_dfa = UrlDFA()
    
    while True:
        url = input("\nEnter a URL to validate (or 'q' to quit): ")
        
        if url.lower() == 'q':
            break
        
        valid, state_sequence = url_dfa.validate_url(url)
        
        print(f"URL is {'valid' if valid else 'invalid'}")
        print(f"State sequence: {' -> '.join(state_sequence)}")
        
        if valid:
            components = url_dfa.analyze_url_components(url)
            if components:
                print("\nURL Components:")
                print(f"Scheme: {components['scheme']}")
                print(f"Authority: {components['authority']}")
                print(f"Path: {components['path']}")
                print(f"Query: {components['query']}")
                print(f"Fragment: {components['fragment']}")
        
        print()


if __name__ == "__main__":
    main()