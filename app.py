from flask import Flask, render_template, request, jsonify
import json
import os
from dfa_simulator import DFA
from enhanced_url_validator import EnhancedUrlDFA

app = Flask(__name__)

# Initialize the URL validator
url_validator = EnhancedUrlDFA()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dfa_simulator')
def dfa_simulator():
    return render_template('dfa_simulator.html')

@app.route('/url_validator')
def url_validator_page():
    return render_template('url_validator.html')

@app.route('/api/validate_url', methods=['POST'])
def validate_url():
    data = request.json
    url = data.get('url', '')
    
    valid, state_sequence = url_validator.validate_url(url)
    security_issues = url_validator.detect_security_issues(url)
    
    result = {
        'valid': valid,
        'state_sequence': state_sequence,
        'security_issues': security_issues
    }
    
    if not valid:
        result['rejection_reason'] = url_validator.get_rejection_reason(url)
    
    if valid:
        components = url_validator.analyze_url_components(url)
        if components:
            result['components'] = components
    
    return jsonify(result)

@app.route('/api/create_dfa', methods=['POST'])
def create_dfa():
    data = request.json
    
    states = set(data.get('states', []))
    alphabet = set(data.get('alphabet', []))
    transition_function = {}
    
    # Convert transition function from frontend format to DFA format
    for transition in data.get('transitions', []):
        state = transition.get('state')
        symbol = transition.get('symbol')
        next_state = transition.get('next_state')
        
        if state and symbol and next_state:
            transition_function[(state, symbol)] = next_state
    
    start_state = data.get('start_state', '')
    accept_states = set(data.get('accept_states', []))
    
    # Create DFA
    try:
        dfa = DFA(states, alphabet, transition_function, start_state, accept_states)
        
        # Save DFA to a temporary file
        filename = f"temp_dfa_{hash(frozenset(states))}.json"
        dfa.save_to_file(filename)
        
        return jsonify({
            'success': True,
            'message': 'DFA created successfully',
            'dfa_id': filename
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error creating DFA: {str(e)}'
        })

@app.route('/api/test_dfa', methods=['POST'])
def test_dfa():
    data = request.json
    dfa_id = data.get('dfa_id', '')
    input_string = data.get('input_string', '')
    
    try:
        # Load DFA from file
        dfa = DFA.load_from_file(dfa_id)
        
        # Process input string
        accepted, state_sequence = dfa.process_string(input_string)
        
        return jsonify({
            'success': True,
            'accepted': accepted,
            'state_sequence': state_sequence
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error testing DFA: {str(e)}'
        })

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    app.run(debug=True)