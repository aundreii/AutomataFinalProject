import re

class EnhancedUrlDFA:
    def __init__(self):
        # Define simplified states for visualization
        self.states = {
            'start',              # Initial state
            'scheme',             # Scheme part (http/https)
            'authority',          # Domain name part
            'path',               # Path part
            'query',              # Query part
            'fragment',           # Fragment part
            'rejected'            # Invalid state
        }
        
        # Define start state and accept states for visualization
        self.start_state = 'start'
        self.accept_states = {'authority', 'path', 'query', 'fragment'}
        
        # URL validation regex pattern
        self.url_pattern = re.compile(
            r'^(https?://)'  # scheme - http:// or https://
            r'([a-zA-Z0-9][-a-zA-Z0-9]*(\.[-a-zA-Z0-9]+)*\.?)'  # domain
            r'(:\d+)?'  # port - optional
            r'(/[-a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%]*)?'  # path - optional
            r'(\?[-a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%]*)?'  # query - optional
            r'(#[-a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%]*)?$',  # fragment - optional
            re.IGNORECASE
        )
        
        # Security patterns to check
        self.security_patterns = {
            'sql_injection': r'(\b(select|insert|update|delete|drop|union|exec|declare|script)\b)|(--)|(\%27)|(\')|(")|(\/\*)|(\*\/)',
            'xss': r'(<script>)|(javascript:)|(\balert\s*\()|(\beval\s*\()|(\bexec\s*\()|(\bonload\s*=)|(\bonerror\s*=)',
            'path_traversal': r'(\.\.\/)|(\.\.\\)|(\.\.%2f)|(\.\.%5c)',
            'command_injection': r'(\|\s*[\w\-]+)|(;\s*[\w\-]+)|(\`[^\`]*\`)',
            'suspicious_chars': r'(\\x[0-9a-fA-F]{2})|(\\u[0-9a-fA-F]{4})|(\\[0-7]{3})',
            'protocol_violation': r'(http[^:]*(:|%3A)(\/\/|%2F%2F))',
            'open_redirect': r'(url=)|(redirect=)|(return=)|(next=)|(to=)|(link=)|(goto=)'
        }
    
    def validate_url(self, url):
        """
        Validate a URL using regex pattern
        
        Parameters:
        - url: the URL to validate
        
        Returns:
        - True if the URL is valid, False otherwise
        - The sequence of states visited (simplified for visualization)
        """
        # Check if URL matches the pattern
        match = self.url_pattern.match(url)
        
        if not match:
            # Determine how far the URL got before failing
            state_sequence = ['start']
            
            # Check if it starts with http or https
            if url.startswith('http'):
                state_sequence.append('scheme')
                
                # Check if it has ://
                if '://' in url:
                    parts = url.split('://', 1)
                    remaining = parts[1]
                    
                    # Check if it has authority
                    if remaining and not remaining.startswith('/'):
                        state_sequence.append('authority')
                        
                        # Check for path, query, fragment
                        if '/' in remaining:
                            state_sequence.append('path')
                        if '?' in remaining:
                            state_sequence.append('query')
                        if '#' in remaining:
                            state_sequence.append('fragment')
            
            state_sequence.append('rejected')
            return False, state_sequence
        
        # Extract components to determine state sequence
        scheme = match.group(1)
        authority = match.group(2)
        path = match.group(4) or ''
        query = match.group(5) or ''
        fragment = match.group(6) or ''
        
        # Build state sequence
        state_sequence = ['start', 'scheme', 'authority']
        
        if path:
            state_sequence.append('path')
        if query:
            state_sequence.append('query')
        if fragment:
            state_sequence.append('fragment')
        
        return True, state_sequence
    
    def analyze_url_components(self, url):
        """
        Analyze and extract components of a valid URL
        
        Parameters:
        - url: the URL to analyze
        
        Returns:
        - Dictionary with URL components or None if invalid
        """
        match = self.url_pattern.match(url)
        
        if not match:
            return None
        
        # Extract URL components
        components = {
            'scheme': match.group(1).rstrip(':/'),
            'authority': match.group(2),
            'path': match.group(4) or '',
            'query': match.group(5) or '',
            'fragment': match.group(6) or ''
        }
        
        return components
    
    def detect_security_issues(self, url):
        """
        Detect potential security issues in a URL
        
        Parameters:
        - url: the URL to analyze
        
        Returns:
        - Dictionary with detected security issues
        """
        security_issues = {}
        
        # Check each security pattern
        for issue_type, pattern in self.security_patterns.items():
            matches = re.findall(pattern, url, re.IGNORECASE)
            if matches:
                security_issues[issue_type] = matches
        
        # Check for excessively long components
        components = self.analyze_url_components(url)
        if components:
            if len(components['path']) > 255:
                security_issues.setdefault('excessive_length', []).append('path')
            if len(components['query']) > 1024:
                security_issues.setdefault('excessive_length', []).append('query')
        
        return security_issues
    
    def get_rejection_reason(self, url):
        """
        Get the reason why a URL was rejected
        
        Parameters:
        - url: the URL to analyze
        
        Returns:
        - String explaining why the URL was rejected
        """
        if not url:
            return "URL cannot be empty"
            
        if not url.startswith('http'):
            return "URL must start with 'http' or 'https'"
            
        if not url.startswith(('http://', 'https://')):
            return "Invalid URL scheme (expected 'http://' or 'https://')"
            
        parts = url.split('://', 1)
        if len(parts) < 2 or not parts[1]:
            return "Missing domain after scheme"
            
        domain_part = parts[1].split('/', 1)[0]
        if not domain_part or domain_part.startswith('.'):
            return "Invalid domain name"
            
        # If we got here but the URL is still invalid, it's likely a formatting issue
        return "URL format is invalid. Please ensure it follows the pattern: http(s)://domain.com/path?query#fragment"


def main():
    print("Enhanced URL Validator with Security Detection")
    print("===========================================\n")
    
    url_dfa = EnhancedUrlDFA()
    
    while True:
        url = input("\nEnter a URL to validate (or 'q' to quit): ")
        
        if url.lower() == 'q':
            break
        
        valid, state_sequence = url_dfa.validate_url(url)
        
        print(f"URL is {'valid' if valid else 'invalid'}")
        
        if not valid:
            rejection_reason = url_dfa.get_rejection_reason(url)
            print(f"Rejection reason: {rejection_reason}")
        
        print(f"State sequence: {' -> '.join(state_sequence)}")
        
        # Check for security issues regardless of validity
        security_issues = url_dfa.detect_security_issues(url)
        if security_issues:
            print("\nPotential security issues detected:")
            for issue_type, details in security_issues.items():
                print(f"- {issue_type.replace('_', ' ').title()}: {details}")
        
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