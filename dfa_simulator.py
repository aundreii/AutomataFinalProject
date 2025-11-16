import json

class DFA:
    def __init__(self, states, alphabet, transition_function, start_state, accept_states):
        """
        Initialize a DFA with its components
        
        Parameters:
        - states: set of states in the DFA
        - alphabet: set of symbols in the alphabet
        - transition_function: dictionary mapping (state, symbol) to next state
        - start_state: the initial state
        - accept_states: set of accepting states
        """
        self.states = states
        self.alphabet = alphabet
        self.transition_function = transition_function
        self.start_state = start_state
        self.accept_states = accept_states
    
    def process_string(self, input_string):
        """
        Process an input string through the DFA
        
        Parameters:
        - input_string: the string to process
        
        Returns:
        - True if the string is accepted, False otherwise
        - The sequence of states visited
        """
        current_state = self.start_state
        state_sequence = [current_state]
        
        for symbol in input_string:
            if symbol not in self.alphabet:
                raise ValueError(f"Symbol '{symbol}' not in alphabet")
            
            if (current_state, symbol) not in self.transition_function:
                return False, state_sequence
            
            current_state = self.transition_function[(current_state, symbol)]
            state_sequence.append(current_state)
        
        return current_state in self.accept_states, state_sequence
    
    def save_to_file(self, filename):
        """
        Save the DFA to a JSON file
        """
        dfa_dict = {
            "states": list(self.states),
            "alphabet": list(self.alphabet),
            "transition_function": {f"{state},{symbol}": next_state 
                                   for (state, symbol), next_state in self.transition_function.items()},
            "start_state": self.start_state,
            "accept_states": list(self.accept_states)
        }
        
        with open(filename, 'w') as f:
            json.dump(dfa_dict, f, indent=4)
    
    @classmethod
    def load_from_file(cls, filename):
        """
        Load a DFA from a JSON file
        """
        with open(filename, 'r') as f:
            dfa_dict = json.load(f)
        
        states = set(dfa_dict["states"])
        alphabet = set(dfa_dict["alphabet"])
        transition_function = {}
        
        for key, value in dfa_dict["transition_function"].items():
            state, symbol = key.split(",")
            transition_function[(state, symbol)] = value
        
        start_state = dfa_dict["start_state"]
        accept_states = set(dfa_dict["accept_states"])
        
        return cls(states, alphabet, transition_function, start_state, accept_states)


def create_dfa_interactive():
    """
    Create a DFA through interactive prompts
    """
    print("=== DFA Creator ===")
    
    # Get states
    states_input = input("Enter states (comma-separated): ")
    states = set(state.strip() for state in states_input.split(','))
    
    # Get alphabet
    alphabet_input = input("Enter alphabet symbols (comma-separated): ")
    alphabet = set(symbol.strip() for symbol in alphabet_input.split(','))
    
    # Get transition function
    transition_function = {}
    print("\nDefine transition function:")
    for state in states:
        for symbol in alphabet:
            next_state = input(f"δ({state}, {symbol}) = ")
            if next_state in states:
                transition_function[(state, symbol)] = next_state
            else:
                print(f"Error: {next_state} is not a valid state. Using a trap state.")
                transition_function[(state, symbol)] = "trap"
    
    # Get start state
    while True:
        start_state = input("\nEnter start state: ")
        if start_state in states:
            break
        print("Error: Start state must be in the set of states.")
    
    # Get accept states
    accept_input = input("\nEnter accept states (comma-separated): ")
    accept_states = set(state.strip() for state in accept_input.split(','))
    
    # Validate accept states
    if not accept_states.issubset(states):
        print("Warning: Some accept states are not in the set of states.")
        accept_states = accept_states.intersection(states)
    
    return DFA(states, alphabet, transition_function, start_state, accept_states)


def main():
    print("DFA Simulator")
    print("=============\n")
    
    while True:
        print("\nOptions:")
        print("1. Create a new DFA")
        print("2. Load a DFA from file")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == '1':
            dfa = create_dfa_interactive()
            
            # Test the DFA
            while True:
                test_string = input("\nEnter a string to test (or 'q' to quit): ")
                if test_string.lower() == 'q':
                    break
                
                try:
                    accepted, state_sequence = dfa.process_string(test_string)
                    print(f"String {'accepted' if accepted else 'rejected'}")
                    print(f"State sequence: {' -> '.join(state_sequence)}")
                except ValueError as e:
                    print(f"Error: {e}")
            
            # Save the DFA
            save = input("\nSave this DFA? (y/n): ")
            if save.lower() == 'y':
                filename = input("Enter filename: ")
                dfa.save_to_file(filename)
                print(f"DFA saved to {filename}")
        
        elif choice == '2':
            filename = input("Enter filename to load: ")
            try:
                dfa = DFA.load_from_file(filename)
                print(f"DFA loaded from {filename}")
                
                # Test the DFA
                while True:
                    test_string = input("\nEnter a string to test (or 'q' to quit): ")
                    if test_string.lower() == 'q':
                        break
                    
                    try:
                        accepted, state_sequence = dfa.process_string(test_string)
                        print(f"String {'accepted' if accepted else 'rejected'}")
                        print(f"State sequence: {' -> '.join(state_sequence)}")
                    except ValueError as e:
                        print(f"Error: {e}")
            
            except FileNotFoundError:
                print(f"Error: File {filename} not found.")
            except json.JSONDecodeError:
                print(f"Error: File {filename} is not a valid JSON file.")
        
        elif choice == '3':
            break
        
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()