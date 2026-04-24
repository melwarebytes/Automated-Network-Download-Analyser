#!/usr/bin/env python3
"""
Report Generator for Network Analysis Results

Generates comprehensive reports from download analysis data:
- Text reports with detailed statistics
- CSV exports for further analysis
- Markdown reports for documentation
- PNG visualizations (requires matplotlib)

Usage:
    python report_generator.py results/results_YYYYMMDD_HHMMSS.json
    python report_generator.py results/*.json --formats text csv markdown
"""

import json
import os
import sys
import statistics
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
import argparse
import glob

# Visualization imports
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("[WARN] matplotlib not available - skipping visualizations")


def load_results(filepath: str) -> Dict:
    """Load results from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")
        sys.exit(1)


def normalize_results(data: Dict) -> Dict:
    """
    Normalize results from different schema versions.

    Handles both old and new result file schemas.
    """
    config = data.get('configuration', {})
    stats = data.get('statistics', {})
    results = data.get('results', [])

    # Helper to get config value (new or legacy schema)
    def get_config(key: str, default=None):
        if key in config:
            return config[key]
        return data.get(key, default)

    # Helper to get stats value (new or legacy schema)
    def get_stats(key: str, default=0):
        if key in stats:
            return stats[key]
        return data.get(key, default)

    normalized = dict(data)
    normalized.update({
        'target_url': get_config('url', 'Unknown'),
        'hostname': get_config('hostname', 'Unknown'),
        'port': get_config('port', 0),
        'protocol': get_config('protocol', 'tcp').upper(),
        'ssl_enabled': get_config('ssl_enabled', False),
        'duration_seconds': get_config('duration_seconds', 0),
        'interval_seconds': get_config('interval_seconds', 0),
        'total_downloads': get_stats('total_downloads', len(results)),
        'successful_downloads': get_stats(
            'successful_downloads',
            len([r for r in results if r.get('success', False)])
        ),
        'failed_downloads': get_stats(
            'failed_downloads',
            len([r for r in results if not r.get('success', False)])
        ),
        'udp_transfers': get_stats(
            'udp_transfers',
            len([r for r in results if r.get('protocol', '').lower() == 'udp'])
        ),
        'results': results
    })

    return normalized


def generate_text_report(data: Dict, output_file: str):
    """Generate detailed text report."""
    data = normalize_results(data)
    lines = []

    # Header
    lines.append("=" * 80)
    lines.append(" " * 25 + "NETWORK DOWNLOAD ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Session ID:     {data['session_id']}")
    lines.append(f"Target URL:     {data['target_url']}")
    lines.append(f"Protocol:       {data['protocol']}{' + SSL' if data.get('ssl_enabled') else ''}")
    lines.append(f"Duration:       {data['duration_seconds']}s")
    lines.append(f"Interval:       {data['interval_seconds']}s")
    lines.append("")

    # Overall statistics
    lines.append("=" * 80)
    lines.append("OVERALL STATISTICS")
    lines.append("=" * 80)
    lines.append(f"Total Downloads:    {data['total_downloads']}")
    lines.append(f"Successful:         {data['successful_downloads']}")
    lines.append(f"Failed:             {data['failed_downloads']}")

    if data['total_downloads'] > 0:
        rate = (data['successful_downloads'] / data['total_downloads']) * 100
        lines.append(f"Success Rate:       {rate:.1f}%")

    # UDP-specific stats
    if data['udp_transfers'] > 0:
        udp_results = [r for r in data['results'] if r.get('protocol', '').lower() == 'udp']
        expected = sum(r.get('packets_expected', 0) for r in udp_results)
        received = sum(r.get('packets_received', 0) for r in udp_results)
        retries = sum(r.get('udp_retries', 0) for r in udp_results)
        retrans = sum(r.get('packets_retransmitted', 0) for r in udp_results)

        lines.append("")
        lines.append("UDP TRANSFER DETAILS:")
        lines.append(f"  UDP Transfers:        {len(udp_results)}")
        lines.append(f"  Packets Received:     {received}/{expected}")
        lines.append(f"  Retries:              {retries}")
        lines.append(f"  Packets Retransmitted: {retrans}")

    lines.append("")

    # Analyze successful downloads
    successful = [r for r in data['results'] if r['success']]

    if successful:
        speeds = [r['download_speed_mbps'] for r in successful]
        times = [r['download_time_seconds'] for r in successful]

        lines.append("=" * 80)
        lines.append("DOWNLOAD SPEED ANALYSIS (Mbps)")
        lines.append("=" * 80)
        lines.append(f"Average Speed:  {statistics.mean(speeds):.2f} Mbps")
        lines.append(f"Median Speed:   {statistics.median(speeds):.2f} Mbps")
        lines.append(f"Minimum Speed:  {min(speeds):.2f} Mbps")
        lines.append(f"Maximum Speed:  {max(speeds):.2f} Mbps")
        lines.append(f"Speed Range:    {max(speeds) - min(speeds):.2f} Mbps")

        if len(speeds) >= 2:
            lines.append(f"Std Deviation:  {statistics.stdev(speeds):.2f} Mbps")

        lines.append("")
        lines.append("=" * 80)
        lines.append("DOWNLOAD TIME ANALYSIS (seconds)")
        lines.append("=" * 80)
        lines.append(f"Average Time:   {statistics.mean(times):.2f}s")
        lines.append(f"Median Time:    {statistics.median(times):.2f}s")
        lines.append(f"Minimum Time:   {min(times):.2f}s")
        lines.append(f"Maximum Time:   {max(times):.2f}s")
        lines.append("")

        # Hourly analysis
        hourly_data = {}
        for result in successful:
            dt = datetime.fromisoformat(result['timestamp'])
            hour = dt.hour
            if hour not in hourly_data:
                hourly_data[hour] = []
            hourly_data[hour].append(result['download_speed_mbps'])

        if hourly_data:
            lines.append("=" * 80)
            lines.append("HOURLY PERFORMANCE ANALYSIS")
            lines.append("=" * 80)
            lines.append(f"{'Hour':<10} {'Downloads':<12} {'Avg (Mbps)':<15} {'Min':<12} {'Max':<12}")
            lines.append("-" * 80)

            for hour in sorted(hourly_data.keys()):
                speeds_hour = hourly_data[hour]
                avg = statistics.mean(speeds_hour)
                lines.append(
                    f"{hour:02d}:00     {len(speeds_hour):<12} {avg:<15.2f} "
                    f"{min(speeds_hour):<12.2f} {max(speeds_hour):<12.2f}"
                )
            lines.append("")

            # Congestion analysis
            hourly_avg = {h: statistics.mean(s) for h, s in hourly_data.items()}
            sorted_hours = sorted(hourly_avg.items(), key=lambda x: x[1])

            lines.append("NETWORK CONGESTION ANALYSIS")
            lines.append("-" * 80)
            lines.append(f"Slowest Period: {sorted_hours[0][0]:02d}:00 (Avg: {sorted_hours[0][1]:.2f} Mbps)")
            lines.append(f"Fastest Period: {sorted_hours[-1][0]:02d}:00 (Avg: {sorted_hours[-1][1]:.2f} Mbps)")

            if sorted_hours[-1][1] > 0:
                degradation = ((sorted_hours[-1][1] - sorted_hours[0][1]) / sorted_hours[-1][1]) * 100
                lines.append(f"Performance Degradation: {degradation:.1f}% during congestion")
            lines.append("")

        # Detailed log
        lines.append("=" * 80)
        lines.append("DETAILED DOWNLOAD LOG")
        lines.append("=" * 80)
        lines.append(f"{'#':<5} {'Timestamp':<22} {'Proto':<8} {'Status':<10} {'Speed':<12} {'Time':<10} {'Size':<10}")
        lines.append("-" * 80)

        for idx, result in enumerate(data['results'], 1):
            ts = datetime.fromisoformat(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            proto = result.get('protocol', 'tcp').upper()
            status = "Success" if result['success'] else "Failed"

            if result['success']:
                speed = f"{result['download_speed_mbps']:.2f}"
                time_s = f"{result['download_time_seconds']:.2f}"
                size = f"{result['file_size_bytes'] / (1024**2):.2f}MB"
            else:
                speed = "N/A"
                time_s = "N/A"
                size = "N/A"

            lines.append(f"{idx:<5} {ts:<22} {proto:<8} {status:<10} {speed:<12} {time_s:<10} {size:<10}")

            # UDP details
            if proto == 'UDP':
                exp = result.get('packets_expected', 0)
                recv = result.get('packets_received', 0)
                ret = result.get('udp_retries', 0)
                lines.append(f"      Packets: {recv}/{exp}, Retries: {ret}")

            # Error details
            if not result['success'] and result.get('error'):
                lines.append(f"      Error: {result['error']}")

        lines.append("")

    # Failed downloads analysis
    failed = [r for r in data['results'] if not r['success']]
    if failed:
        lines.append("=" * 80)
        lines.append("FAILED DOWNLOADS ANALYSIS")
        lines.append("=" * 80)

        error_types = {}
        for result in failed:
            error = result.get('error', 'Unknown')
            error_types[error] = error_types.get(error, 0) + 1

        lines.append("Error Summary:")
        for error, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {error}: {count} occurrence(s)")
        lines.append("")

    # Save report
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))

    print(f"[OK] Text report saved: {output_file}")


def generate_csv_export(data: Dict, output_file: str):
    """Export results to CSV format."""
    data = normalize_results(data)
    lines = []

    # Header
    lines.append(
        "Download_Number,Timestamp,Protocol,Success,Status_Code,File_Size_Bytes,"
        "File_Size_MB,Download_Time_Seconds,Speed_Mbps,Connection_Time_MS,"
        "SSL_Handshake_MS,Packets_Expected,Packets_Received,UDP_Retries,"
        "Packets_Retransmitted,Error,Error_Type,MD5_Checksum"
    )

    for idx, result in enumerate(data['results'], 1):
        proto = result.get('protocol', 'tcp').upper()
        line = (
            f"{idx},"
            f"{result['timestamp']},"
            f"{proto},"
            f"{'TRUE' if result['success'] else 'FALSE'},"
            f"{result.get('status_code', '')},"
            f"{result.get('file_size_bytes', 0)},"
            f"{result.get('file_size_bytes', 0) / (1024**2):.2f},"
            f"{result.get('download_time_seconds', 0):.2f},"
            f"{result.get('download_speed_mbps', 0):.2f},"
            f"{result.get('connection_time_ms', 0):.2f},"
            f"{result.get('ssl_handshake_time_ms', 0):.2f},"
            f"{result.get('packets_expected', 0)},"
            f"{result.get('packets_received', 0)},"
            f"{result.get('udp_retries', 0)},"
            f"{result.get('packets_retransmitted', 0)},"
            f"\"{(result.get('error') or '').replace(',', ';')}\","
            f"{result.get('error_type', '')},"
            f"{result.get('md5_checksum', '')}"
        )
        lines.append(line)

    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))

    print(f"[OK] CSV export saved: {output_file}")


def generate_markdown_report(data: Dict, output_file: str):
    """Generate Markdown report."""
    data = normalize_results(data)
    md = []

    md.append("# Network Download Analysis Report")
    md.append("")
    md.append(f"**Session ID:** {data['session_id']}")
    md.append(f"**Target:** {data['target_url']}")
    md.append(f"**Protocol:** {data['protocol']}{' + SSL' if data.get('ssl_enabled') else ''}")
    md.append(f"**Duration:** {data['duration_seconds'] / 3600:.1f} hours")
    md.append("")

    md.append("## Summary Statistics")
    md.append("")
    md.append(f"- **Total Downloads:** {data['total_downloads']}")
    md.append(f"- **Successful:** {data['successful_downloads']}")
    md.append(f"- **Failed:** {data['failed_downloads']}")

    if data['total_downloads'] > 0:
        rate = (data['successful_downloads'] / data['total_downloads']) * 100
        md.append(f"- **Success Rate:** {rate:.1f}%")

    if data['udp_transfers'] > 0:
        udp_results = [r for r in data['results'] if r.get('protocol', '').lower() == 'udp']
        expected = sum(r.get('packets_expected', 0) for r in udp_results)
        received = sum(r.get('packets_received', 0) for r in udp_results)
        md.append(f"- **UDP Transfers:** {len(udp_results)}")
        md.append(f"- **UDP Packets:** {received}/{expected}")

    md.append("")

    successful = [r for r in data['results'] if r['success']]

    if successful:
        speeds = [r['download_speed_mbps'] for r in successful]

        md.append("## Performance Metrics")
        md.append("")
        md.append(f"- **Average Speed:** {statistics.mean(speeds):.2f} Mbps")
        md.append(f"- **Minimum Speed:** {min(speeds):.2f} Mbps")
        md.append(f"- **Maximum Speed:** {max(speeds):.2f} Mbps")
        md.append(f"- **Speed Range:** {max(speeds) - min(speeds):.2f} Mbps")
        md.append("")

        # Hourly table
        hourly_data = defaultdict(list)
        for result in successful:
            hour = datetime.fromisoformat(result['timestamp']).hour
            hourly_data[hour].append(result['download_speed_mbps'])

        if hourly_data:
            md.append("## Hourly Performance")
            md.append("")
            md.append("| Hour | Downloads | Avg Speed (Mbps) | Min | Max |")
            md.append("|------|-----------|------------------|-----|-----|")

            for hour in sorted(hourly_data.keys()):
                speeds_hour = hourly_data[hour]
                avg = statistics.mean(speeds_hour)
                md.append(
                    f"| {hour:02d}:00 | {len(speeds_hour)} | {avg:.2f} | "
                    f"{min(speeds_hour):.2f} | {max(speeds_hour):.2f} |"
                )
            md.append("")

    with open(output_file, 'w') as f:
        f.write('\n'.join(md))

    print(f"[OK] Markdown report saved: {output_file}")


def generate_visualizations(data: Dict, output_dir: str, session_id: str):
    """Generate visualization charts from download data."""
    if not MATPLOTLIB_AVAILABLE:
        print("  [WARN] Skipping visualizations (matplotlib not installed)")
        return

    data = normalize_results(data)
    results = data['results']
    successful = [r for r in results if r.get('success', False)]

    if len(successful) < 2:
        print("  [WARN] Not enough data for visualizations (need 2+ successful downloads)")
        return

    # Prepare data
    timestamps = [datetime.fromisoformat(r['timestamp']) for r in successful]
    speeds = [r['download_speed_mbps'] for r in successful]

    # Group by hour
    hourly_data = defaultdict(list)
    for r in successful:
        hour = datetime.fromisoformat(r['timestamp']).hour
        hourly_data[hour].append(r['download_speed_mbps'])

    hours = sorted(hourly_data.keys())
    hourly_avg = [statistics.mean(hourly_data[h]) for h in hours]

    # Set style
    style_name = 'seaborn-v0_8-darkgrid' if 'seaborn-v0_8-darkgrid' in plt.style.available else 'default'
    plt.style.use(style_name)

    # Create figure with 3 subplots
    fig = plt.figure(figsize=(15, 12))

    # Chart 1: Speed Over Time
    ax1 = plt.subplot(3, 1, 1)
    ax1.plot(timestamps, speeds, marker='o', linewidth=2, markersize=6,
             color='#2E75B6', label='Download Speed')
    ax1.axhline(y=statistics.mean(speeds), color='#D55E00', linestyle='--',
                linewidth=2, label=f'Average: {statistics.mean(speeds):.1f} Mbps')
    ax1.set_xlabel('Time', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Speed (Mbps)', fontsize=12, fontweight='bold')
    ax1.set_title('Network Download Speed Over Time', fontsize=14, fontweight='bold', pad=20)
    ax1.legend(loc='upper right', fontsize=10)
    ax1.grid(True, alpha=0.3)

    if len(timestamps) > 10:
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(timestamps) // 10)))
    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')

    # Chart 2: Average Speed Per Hour
    ax2 = plt.subplot(3, 1, 2)
    colors = ['#27AE60' if s >= statistics.mean(hourly_avg) else '#E74C3C' for s in hourly_avg]
    bars = ax2.bar(hours, hourly_avg, color=colors, alpha=0.7, edgecolor='black', linewidth=1.5)

    for bar, speed in zip(bars, hourly_avg):
        ax2.text(bar.get_x() + bar.get_width() / 2., bar.get_height(),
                 f'{speed:.1f}', ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax2.axhline(y=statistics.mean(hourly_avg), color='#D55E00', linestyle='--',
                linewidth=2, label=f'Overall Average: {statistics.mean(hourly_avg):.1f} Mbps')
    ax2.set_xlabel('Hour of Day', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Average Speed (Mbps)', fontsize=12, fontweight='bold')
    ax2.set_title('Average Download Speed by Hour', fontsize=14, fontweight='bold', pad=20)
    ax2.set_xticks(hours)
    ax2.set_xticklabels([f'{h:02d}:00' for h in hours], rotation=45, ha='right')
    ax2.legend(loc='upper right', fontsize=10)
    ax2.grid(True, alpha=0.3, axis='y')

    # Chart 3: Speed Distribution
    ax3 = plt.subplot(3, 1, 3)
    n, bins, patches = ax3.hist(speeds, bins=min(15, len(speeds) // 2 + 1),
                                 color='#3498DB', alpha=0.7, edgecolor='black', linewidth=1.5)

    mean_speed = statistics.mean(speeds)
    for i, patch in enumerate(patches):
        if bins[i] < mean_speed:
            patch.set_facecolor('#E74C3C')
        else:
            patch.set_facecolor('#27AE60')

    ax3.axvline(x=mean_speed, color='#D55E00', linestyle='--',
                linewidth=2, label=f'Mean: {mean_speed:.1f} Mbps')
    ax3.axvline(x=statistics.median(speeds), color='#9B59B6', linestyle='--',
                linewidth=2, label=f'Median: {statistics.median(speeds):.1f} Mbps')
    ax3.set_xlabel('Download Speed (Mbps)', fontsize=12, fontweight='bold')
    ax3.set_ylabel('Frequency', fontsize=12, fontweight='bold')
    ax3.set_title('Download Speed Distribution', fontsize=14, fontweight='bold', pad=20)
    ax3.legend(loc='upper right', fontsize=10)
    ax3.grid(True, alpha=0.3, axis='y')

    # Statistics box
    stats_text = (
        f"Statistics Summary:\n"
        f"  Downloads: {len(successful)}\n"
        f"  Avg Speed: {statistics.mean(speeds):.2f} Mbps\n"
        f"  Median: {statistics.median(speeds):.2f} Mbps\n"
        f"  Std Dev: {statistics.stdev(speeds) if len(speeds) > 1 else 0:.2f} Mbps\n"
        f"  Min: {min(speeds):.2f} Mbps\n"
        f"  Max: {max(speeds):.2f} Mbps"
    )

    fig.text(0.99, 0.01, stats_text, fontsize=9, verticalalignment='bottom',
             horizontalalignment='right', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    plt.tight_layout(rect=[0, 0.03, 1, 0.97])

    output_file = f"{output_dir}/visualizations_{session_id}.png"
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"[OK] Visualizations saved: {output_file}")

    # Hourly ranking chart (separate file)
    fig2, ax = plt.subplots(figsize=(12, 6))

    sorted_pairs = sorted(zip(hours, hourly_avg), key=lambda x: x[1], reverse=True)
    sorted_hours, sorted_speeds = zip(*sorted_pairs) if sorted_pairs else ([], [])

    colors_sorted = ['#27AE60' if i < len(sorted_speeds) // 2 else '#E74C3C'
                     for i in range(len(sorted_speeds))]

    bars = ax.barh(range(len(sorted_hours)), sorted_speeds, color=colors_sorted,
                   alpha=0.7, edgecolor='black', linewidth=1.5)
    ax.set_yticks(range(len(sorted_hours)))
    ax.set_yticklabels([f'{h:02d}:00' for h in sorted_hours])
    ax.set_xlabel('Average Speed (Mbps)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Hour of Day', fontsize=12, fontweight='bold')
    ax.set_title('Network Performance Ranking by Hour', fontsize=14, fontweight='bold', pad=20)

    for bar, speed in zip(bars, sorted_speeds):
        ax.text(bar.get_width(), bar.get_y() + bar.get_height() / 2.,
                f' {speed:.1f} Mbps', ha='left', va='center', fontsize=9, fontweight='bold')

    ax.axvline(x=statistics.mean(hourly_avg), color='#D55E00', linestyle='--',
               linewidth=2, label=f'Average: {statistics.mean(hourly_avg):.1f} Mbps')
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(True, alpha=0.3, axis='x')

    plt.tight_layout()
    output_file2 = f"{output_dir}/hourly_ranking_{session_id}.png"
    plt.savefig(output_file2, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"[OK] Hourly ranking saved: {output_file2}")


def save_json(data: Dict, output_dir: str) -> str:
    """Save results data as a JSON file. Returns the path written."""
    os.makedirs(output_dir, exist_ok=True)
    session_id = data['session_id']
    filepath = os.path.join(output_dir, f"results_{session_id}.json")
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON saved: {filepath}")
    return filepath


def generate_all(data: Dict, output_dir: str, json_dir: str = "results"):
    """
    Save the JSON results file and generate all report formats.

    Args:
        data: Raw results dict (as built by NetworkDownloadAnalyzer)
        output_dir: Directory for text/csv/markdown/png reports
        json_dir: Directory for the JSON results file
    """
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(json_dir, exist_ok=True)

    save_json(data, json_dir)

    data = normalize_results(data)
    session_id = data['session_id']

    generate_text_report(data, os.path.join(output_dir, f"report_{session_id}.txt"))
    generate_csv_export(data, os.path.join(output_dir, f"data_{session_id}.csv"))
    generate_markdown_report(data, os.path.join(output_dir, f"report_{session_id}.md"))
    generate_visualizations(data, output_dir, session_id)


def main():
    parser = argparse.ArgumentParser(
        description='Generate reports from network analysis results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all report formats
  python report_generator.py results/results_20260410_120000.json

  # Generate specific formats
  python report_generator.py results/*.json --formats text csv markdown

  # Custom output directory
  python report_generator.py results/*.json --output-dir reports
        """
    )

    parser.add_argument(
        'input',
        help='Path to results JSON file (or glob pattern)'
    )

    parser.add_argument(
        '-o', '--output-dir',
        default='reports',
        help='Output directory (default: reports)'
    )

    parser.add_argument(
        '--formats',
        nargs='+',
        choices=['text', 'csv', 'markdown', 'all'],
        default=['all'],
        help='Report formats (default: all)'
    )

    parser.add_argument(
        '--json-dir',
        default=None,
        help='Directory to save JSON results (default: same directory as input file)'
    )

    args = parser.parse_args()

    # Handle glob patterns
    import glob
    input_files = glob.glob(args.input)

    if not input_files:
        print(f"ERROR: No files found matching: {args.input}")
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Process each file
    for filepath in input_files:
        print(f"\nProcessing: {filepath}")

        data = load_results(filepath)

        # Save JSON to --json-dir (or the input file's own directory if not specified)
        json_dir = args.json_dir or os.path.dirname(os.path.abspath(filepath))
        save_json(data, json_dir)

        data = normalize_results(data)
        session_id = data['session_id']
        formats = args.formats if 'all' not in args.formats else ['text', 'csv', 'markdown']

        if 'text' in formats:
            generate_text_report(data, os.path.join(args.output_dir, f"report_{session_id}.txt"))

        if 'csv' in formats:
            generate_csv_export(data, os.path.join(args.output_dir, f"data_{session_id}.csv"))

        if 'markdown' in formats:
            generate_markdown_report(data, os.path.join(args.output_dir, f"report_{session_id}.md"))

        print("\nGenerating visualizations...")
        generate_visualizations(data, args.output_dir, session_id)

    print("\n[OK] Report generation complete!")


if __name__ == '__main__':
    main()
