#!/usr/bin/env python3
"""
NIST CSF 2.0 Control Extractor

This script extracts specific controls from the NIST Cybersecurity Framework 2.0 
OSCAL JSON file and creates a tailored version containing only the specified controls.
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any


def load_nist_csf_file(file_path: str) -> Dict[str, Any]:
    """
    Load the NIST CSF JSON file.
    
    Args:
        file_path: Path to the NIST CSF JSON file
        
    Returns:
        Dictionary containing the parsed JSON data
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If the file is not valid JSON
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"NIST CSF file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in file {file_path}: {e}")


def extract_controls_by_id(data: Dict[str, Any], control_ids: List[str]) -> Dict[str, Any]:
    """
    Extract specific controls from the NIST CSF data structure.
    
    Args:
        data: The complete NIST CSF data structure
        control_ids: List of control IDs to extract (e.g., ['ID.AM-03', 'PR.DS-01'])
        
    Returns:
        Modified data structure containing only the specified controls
    """
    # Create a copy of the original data structure
    filtered_data = data.copy()
    
    # Extract the security controls array
    if 'catalog' not in data or 'securityControls' not in data['catalog']:
        raise ValueError("Invalid NIST CSF structure: missing catalog.securityControls")
    
    original_controls = data['catalog']['securityControls']
    
    # Filter controls by control ID
    filtered_controls = []
    found_ids = set()
    
    for control in original_controls:
        if control.get('controlId') in control_ids:
            filtered_controls.append(control)
            found_ids.add(control.get('controlId'))
    
    # Check for missing control IDs
    missing_ids = set(control_ids) - found_ids
    if missing_ids:
        print(f"Warning: The following control IDs were not found: {sorted(missing_ids)}")
    
    # Update the data structure with filtered controls
    filtered_data['catalog']['securityControls'] = filtered_controls
    
    # Update metadata to reflect the filtering
    if 'catalog' in filtered_data:
        original_title = filtered_data['catalog'].get('title', 'NIST CSF 2.0')
        filtered_data['catalog']['title'] = f"{original_title} (Filtered - {len(filtered_controls)} controls)"
        
        # Update description to mention filtering
        original_description = filtered_data['catalog'].get('description', '')
        filtered_data['catalog']['description'] = (
            f"{original_description}\n\n"
            f"<p><strong>Note:</strong> This is a filtered version containing only "
            f"{len(filtered_controls)} specific controls extracted from the original framework.</p>"
        )
    
    return filtered_data


def save_filtered_controls(data: Dict[str, Any], output_path: str) -> None:
    """
    Save the filtered controls to a new JSON file.
    
    Args:
        data: The filtered data structure
        output_path: Path where the filtered file should be saved
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
        print(f"Filtered controls saved to: {output_path}")
    except Exception as e:
        raise Exception(f"Error saving filtered controls: {e}")


def print_control_summary(data: Dict[str, Any]) -> None:
    """
    Print a summary of the extracted controls.
    
    Args:
        data: The filtered data structure
    """
    controls = data.get('catalog', {}).get('securityControls', [])
    
    print(f"\nExtracted {len(controls)} controls:")
    print("-" * 80)
    
    for control in controls:
        control_id = control.get('controlId', 'Unknown')
        title = control.get('title', 'No title')
        family = control.get('family', 'Unknown family')
        
        print(f"ID: {control_id}")
        print(f"Family: {family}")
        print(f"Title: {title}")
        print("-" * 80)


def main():
    """Main function to run the control extraction."""
    
    # Define the specific controls to extract
    TARGET_CONTROL_IDS = [
        'ID.AM-03', 'ID.AM-07', 'ID.AM-08', 'ID.IM-01', 'ID.IM-02', 'ID.IM-03',
        'ID.RA-01', 'ID.RA-07', 'PR.AA-05', 'PR.DS-01', 'PR.DS-02', 'PR.DS-10',
        'PR.IR-01', 'PR.PS-01', 'PR.PS-05', 'DE.AE-02', 'DE.AE-03', 'DE.CM-01',
        'DE.CM-02', 'DE.CM-03', 'DE.CM-06', 'DE.CM-09'
    ]
    
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description='Extract specific controls from NIST CSF 2.0 JSON file'
    )
    parser.add_argument(
        '--input', '-i',
        default='nist-csf-2.json',
        help='Input NIST CSF JSON file path (default: nist-csf-2.json)'
    )
    parser.add_argument(
        '--output', '-o',
        default='nist-csf-2-filtered.json',
        help='Output file path for filtered controls (default: nist-csf-2-filtered.json)'
    )
    parser.add_argument(
        '--controls', '-c',
        nargs='*',
        help='Custom list of control IDs to extract (overrides default list)'
    )
    parser.add_argument(
        '--summary', '-s',
        action='store_true',
        help='Print summary of extracted controls'
    )
    
    args = parser.parse_args()
    
    # Use custom control list if provided, otherwise use default
    control_ids = args.controls if args.controls else TARGET_CONTROL_IDS
    
    try:
        # Load the NIST CSF file
        print(f"Loading NIST CSF file: {args.input}")
        nist_data = load_nist_csf_file(args.input)
        
        # Extract the specified controls
        print(f"Extracting {len(control_ids)} specified controls...")
        filtered_data = extract_controls_by_id(nist_data, control_ids)
        
        # Save the filtered controls
        save_filtered_controls(filtered_data, args.output)
        
        # Print summary if requested
        if args.summary:
            print_control_summary(filtered_data)
        
        print(f"\nSuccessfully extracted {len(filtered_data['catalog']['securityControls'])} controls")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())