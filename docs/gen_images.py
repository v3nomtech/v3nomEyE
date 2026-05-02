"""Generate all README visual assets for VenomEye."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.gridspec as gridspec
import numpy as np
import os

OUT = os.path.dirname(os.path.abspath(__file__))

DARK_BG   = '#0d1117'
CARD_BG   = '#161b22'
BORDER    = '#30363d'
RED       = '#f85149'
ORANGE    = '#e3b341'
GREEN     = '#3fb950'
BLUE      = '#58a6ff'
PURPLE    = '#bc8cff'
CYAN      = '#79c0ff'
GRAY      = '#8b949e'
WHITE     = '#e6edf3'


# ─────────────────────────────────────────────────────────────────────────────
# 1. BANNER
# ─────────────────────────────────────────────────────────────────────────────
def gen_banner():
    fig, ax = plt.subplots(figsize=(16, 4))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, 16); ax.set_ylim(0, 4)
    ax.axis('off')

    # Glow background rectangle
    for alpha, lw in [(0.06, 40), (0.10, 20), (0.18, 8)]:
        ax.add_patch(FancyBboxPatch((0.2, 0.2), 15.6, 3.6,
                                    boxstyle='round,pad=0.1',
                                    linewidth=lw, edgecolor=RED,
                                    facecolor='none', alpha=alpha))

    ax.add_patch(FancyBboxPatch((0.2, 0.2), 15.6, 3.6,
                                boxstyle='round,pad=0.1',
                                linewidth=1.5, edgecolor=RED,
                                facecolor=CARD_BG, alpha=1.0))

    # Title
    ax.text(8, 2.55, 'VENOMEYE', fontsize=68, fontweight='bold',
            ha='center', va='center', color=RED,
            fontfamily='monospace',
            path_effects=[pe.withStroke(linewidth=6, foreground='#3d0000')])

    # Subtitle
    ax.text(8, 1.45, 'P1 Bug Bounty Reconnaissance & Exploitation Framework',
            fontsize=15, ha='center', va='center', color=WHITE,
            fontfamily='monospace')

    # Tag line
    ax.text(8, 0.75, '17 Phases  •  10 Scanners  •  15+ Vuln Classes  •  Kali Linux',
            fontsize=10.5, ha='center', va='center', color=GRAY,
            fontfamily='monospace')

    # Corner accent dots
    for x, y in [(0.5, 0.5), (15.5, 0.5), (0.5, 3.5), (15.5, 3.5)]:
        ax.plot(x, y, 'o', color=RED, markersize=6, alpha=0.8)

    plt.tight_layout(pad=0)
    fig.savefig(os.path.join(OUT, 'banner.png'), dpi=150,
                bbox_inches='tight', facecolor=DARK_BG)
    plt.close()
    print('[+] banner.png')


# ─────────────────────────────────────────────────────────────────────────────
# 2. 17-PHASE PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
def gen_pipeline():
    phases = [
        ('1\nSubdomain\nEnum',     BLUE),
        ('2\nDNS Probe\n& httpx',  BLUE),
        ('3\nPort\nScan',          BLUE),
        ('4\nURL\nDiscovery',      BLUE),
        ('5\nNuclei\nCVE',         RED),
        ('6\nManual\nP1 Checks',   RED),
        ('7\nSSL/TLS\nAnalysis',   GREEN),
        ('8\nCVE\nExploits',       RED),
        ('9\nJS Deep\nAnalysis',   ORANGE),
        ('10\nSSRF\nActive',       RED),
        ('11\nXSS/SQLi\nSSTI',     RED),
        ('12\nCloud\nMisconfig',   CYAN),
        ('13\nAPI\nSecurity',      PURPLE),
        ('14\nIDOR/BOLA\nHunter',  PURPLE),
        ('15\nSubdomain\nMonitor', GREEN),
        ('16\nHTML/MD\nReport',    ORANGE),
        ('17\nFinal\nSummary',     GREEN),
    ]

    cols = 9
    rows = 2
    fig, ax = plt.subplots(figsize=(20, 6.5))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, cols * 2.1 + 0.3)
    ax.set_ylim(0, rows * 3 + 0.8)
    ax.axis('off')

    ax.text((cols * 2.1 + 0.3) / 2, rows * 3 + 0.3,
            'VenomEye — 17-Phase Recon Pipeline',
            fontsize=15, fontweight='bold', ha='center', va='center',
            color=WHITE, fontfamily='monospace')

    for i, (label, color) in enumerate(phases):
        row = i // cols
        col = i % cols
        x = col * 2.1 + 0.2
        y = (rows - 1 - row) * 3 + 0.4

        # Glow effect
        for alpha, lw in [(0.08, 10), (0.15, 5)]:
            ax.add_patch(FancyBboxPatch((x, y), 1.75, 2.3,
                                        boxstyle='round,pad=0.08',
                                        linewidth=lw, edgecolor=color,
                                        facecolor='none', alpha=alpha))
        ax.add_patch(FancyBboxPatch((x, y), 1.75, 2.3,
                                    boxstyle='round,pad=0.08',
                                    linewidth=1.2, edgecolor=color,
                                    facecolor=CARD_BG, alpha=1.0))

        ax.text(x + 0.875, y + 1.15, label,
                fontsize=7.5, ha='center', va='center',
                color=color, fontfamily='monospace',
                fontweight='bold', linespacing=1.4)

        # Arrow to next (same row)
        if (i + 1) % cols != 0 and i + 1 < len(phases):
            ax.annotate('', xy=(x + 1.75 + 0.35 - 0.02, y + 1.15),
                        xytext=(x + 1.75 + 0.02, y + 1.15),
                        arrowprops=dict(arrowstyle='->', color=GRAY,
                                        lw=1.2, mutation_scale=12))

    # Legend
    legend_items = [
        (BLUE,   'Passive Recon'),
        (RED,    'Active Exploit'),
        (GREEN,  'Assessment / Monitor'),
        (ORANGE, 'Analysis / Report'),
        (CYAN,   'Cloud'),
        (PURPLE, 'Auth / API'),
    ]
    for idx, (c, lbl) in enumerate(legend_items):
        bx = 0.4 + idx * 3.2
        ax.add_patch(FancyBboxPatch((bx, 0.05), 0.3, 0.3,
                                    boxstyle='round,pad=0.03',
                                    facecolor=c, edgecolor='none'))
        ax.text(bx + 0.42, 0.20, lbl, fontsize=8, va='center',
                color=WHITE, fontfamily='monospace')

    plt.tight_layout(pad=0.3)
    fig.savefig(os.path.join(OUT, 'pipeline.png'), dpi=150,
                bbox_inches='tight', facecolor=DARK_BG)
    plt.close()
    print('[+] pipeline.png')


# ─────────────────────────────────────────────────────────────────────────────
# 3. ARCHITECTURE / DATA FLOW
# ─────────────────────────────────────────────────────────────────────────────
def box(ax, x, y, w, h, label, sub='', color=BLUE, fontsize=9):
    for alpha, lw in [(0.07, 10), (0.14, 5)]:
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                                    boxstyle='round,pad=0.05',
                                    linewidth=lw, edgecolor=color,
                                    facecolor='none', alpha=alpha))
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle='round,pad=0.05',
                                linewidth=1.2, edgecolor=color,
                                facecolor=CARD_BG))
    ax.text(x + w / 2, y + h * (0.62 if sub else 0.5),
            label, fontsize=fontsize, fontweight='bold',
            ha='center', va='center', color=color,
            fontfamily='monospace')
    if sub:
        ax.text(x + w / 2, y + h * 0.28, sub, fontsize=7,
                ha='center', va='center', color=GRAY,
                fontfamily='monospace')


def arrow(ax, x1, y1, x2, y2, color=GRAY):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=color,
                                lw=1.1, mutation_scale=11,
                                connectionstyle='arc3,rad=0.0'))


def gen_architecture():
    fig, ax = plt.subplots(figsize=(18, 11))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, 18); ax.set_ylim(0, 11)
    ax.axis('off')

    ax.text(9, 10.5, 'VenomEye — Architecture & Data Flow',
            fontsize=14, fontweight='bold', ha='center', va='center',
            color=WHITE, fontfamily='monospace')

    # Orchestrator
    box(ax, 6.5, 9.0, 5, 1.1, 'venomeye.py',
        '17-Phase Orchestrator', RED, fontsize=11)

    # Phases block
    box(ax, 5.0, 7.5, 8, 1.1,
        'Phases 1 – 8: Passive Recon → Active Scanning',
        'subfinder · amass · dnsx · httpx · naabu · nmap · katana · gau · nuclei · testssl',
        BLUE, fontsize=9)

    arrow(ax, 9, 9.0, 9, 8.6)

    # Intermediate files row
    files = [
        ('subdomains_all.txt', 1.0,  6.3),
        ('live_hosts.txt',     4.0,  6.3),
        ('urls_all.txt',       7.0,  6.3),
        ('params.txt',         10.0, 6.3),
        ('js_files.txt',       13.0, 6.3),
        ('ssrf_candidates.txt',16.0, 6.3),
    ]
    for lbl, x, y in files:
        box(ax, x, y, 2.5, 0.75, lbl, '', CYAN, fontsize=7)
        arrow(ax, 9, 7.5, x + 1.25, y + 0.75)

    # Scanners row
    scanners = [
        ('js_analyzer.py',         'JS Secrets\n& Endpoints',   ORANGE, 1.0,  4.7),
        ('cloud_misconfig.py',      'Cloud\nMisconfigs',         CYAN,   4.0,  4.7),
        ('api_tester.py',           'API Security\nSwagger/JWT', PURPLE, 7.0,  4.7),
        ('xss_sqli_scanner.py',     'XSS · SQLi\nSSTI · Redirect', RED, 10.0, 4.7),
        ('ssrf_tester.py',          'SSRF Active\n+ OOB',        RED,   13.0, 4.7),
        ('idor_hunter.py',          'IDOR/BOLA\nAccess Control', PURPLE, 16.0, 4.7),
    ]
    scanner_file_map = [
        (13.0, 6.3, 1.0,  4.7),   # js_files → js_analyzer
        (1.0,  6.3, 4.0,  4.7),   # subdomains → cloud
        (4.0,  6.3, 7.0,  4.7),   # live_hosts → api
        (10.0, 6.3, 10.0, 4.7),   # params → xss_sqli
        (16.0, 6.3, 13.0, 4.7),   # ssrf_cand → ssrf_tester
        (7.0,  6.3, 16.0, 4.7),   # urls_all → idor
    ]
    for (fx, fy, sx, sy) in scanner_file_map:
        arrow(ax, fx + 1.25, fy, sx + 1.25, sy + 1.1, GRAY)

    for lbl, sub, color, x, y in scanners:
        box(ax, x, y, 2.5, 1.1, lbl, sub, color, fontsize=7.5)

    # Findings JSON
    box(ax, 5.5, 3.2, 7, 0.9,
        'findings.json  (per scanner)',
        'machine-readable severity-tagged vulnerability records',
        ORANGE, fontsize=9)

    for _, _, color, x, y in scanners:
        arrow(ax, x + 1.25, y, 9, 4.1, color)

    # report_builder
    box(ax, 6.5, 1.9, 5, 0.95,
        'report_builder.py',
        'HTML aggregation · severity charts · dedup · PoC snippets',
        GREEN, fontsize=9)
    arrow(ax, 9, 3.2, 9, 2.85)

    # Outputs
    outputs = [
        ('report.html',  GREEN,  6.5,  0.6),
        ('report.md',    BLUE,   9.2,  0.6),
        ('findings.json', ORANGE, 11.9, 0.6),
    ]
    for lbl, color, x, y in outputs:
        box(ax, x, y, 2.4, 0.75, lbl, '', color, fontsize=8)
        arrow(ax, 9, 1.9, x + 1.2, y + 0.75)

    # subdomain_monitor (side)
    box(ax, 0.2, 4.7, 2.2, 1.1,
        'subdomain\nmonitor.py',
        'Slack/Discord\nalerts · delta',
        GREEN, fontsize=7.5)
    arrow(ax, 1.0 + 1.25, 6.3 + 0.375, 1.3, 5.8, GREEN)

    plt.tight_layout(pad=0.3)
    fig.savefig(os.path.join(OUT, 'architecture.png'), dpi=150,
                bbox_inches='tight', facecolor=DARK_BG)
    plt.close()
    print('[+] architecture.png')


# ─────────────────────────────────────────────────────────────────────────────
# 4. VULNERABILITY COVERAGE RADAR
# ─────────────────────────────────────────────────────────────────────────────
def gen_radar():
    categories = [
        'XSS', 'SQLi', 'SSTI', 'SSRF', 'IDOR/BOLA',
        'JWT Attacks', 'Cloud Misconfig', 'JS Secrets',
        'API Security', 'Open Redirect', 'CORS', 'Subdomain Takeover',
        'SSL/TLS', 'CVE Scanning', 'Port Exposure',
    ]
    scores = [9, 9, 8, 9, 9, 8, 9, 9, 8, 8, 8, 7, 8, 9, 8]

    N = len(categories)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]
    scores_plot = scores + scores[:1]

    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)

    # Grid rings
    for r in range(2, 11, 2):
        ring = np.linspace(0, 2 * np.pi, 300)
        ax.plot(ring, [r] * 300, color=BORDER, lw=0.6, alpha=0.7)
    ax.set_ylim(0, 10)

    # Spokes
    for angle in angles[:-1]:
        ax.plot([angle, angle], [0, 10], color=BORDER, lw=0.6, alpha=0.7)

    # Fill
    ax.fill(angles, scores_plot, color=RED, alpha=0.18)
    ax.plot(angles, scores_plot, color=RED, lw=2.0)
    for a, s in zip(angles[:-1], scores):
        ax.plot(a, s, 'o', color=RED, markersize=7,
                markerfacecolor=RED, markeredgecolor=WHITE, markeredgewidth=1)

    # Labels
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=9.5, fontfamily='monospace',
                       color=WHITE, fontweight='bold')
    ax.tick_params(axis='x', pad=14)
    ax.set_yticks([2, 4, 6, 8, 10])
    ax.set_yticklabels(['2', '4', '6', '8', '10'],
                       fontsize=7, color=GRAY, fontfamily='monospace')

    ax.spines['polar'].set_visible(False)
    ax.grid(False)

    ax.set_title('Vulnerability Coverage Map', fontsize=14, fontweight='bold',
                 color=WHITE, fontfamily='monospace', pad=28)

    fig.text(0.5, 0.01, 'Score = automation depth / coverage breadth (out of 10)',
             ha='center', fontsize=8.5, color=GRAY, fontfamily='monospace')

    plt.tight_layout(pad=1.5)
    fig.savefig(os.path.join(OUT, 'coverage_radar.png'), dpi=150,
                bbox_inches='tight', facecolor=DARK_BG)
    plt.close()
    print('[+] coverage_radar.png')


# ─────────────────────────────────────────────────────────────────────────────
# 5. OUTPUT FORMAT SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
def gen_output_summary():
    fig, ax = plt.subplots(figsize=(14, 7))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, 14); ax.set_ylim(0, 7)
    ax.axis('off')

    ax.text(7, 6.55, 'VenomEye — Scanner Outputs & Severity Distribution',
            fontsize=13, fontweight='bold', ha='center', va='center',
            color=WHITE, fontfamily='monospace')

    scanners = [
        ('venomeye.py',         RED,    ['subdomains_all.txt', 'live_hosts.txt', 'urls_all.txt', 'params.txt', 'nuclei_crit.txt']),
        ('xss_sqli_scanner',    RED,    ['findings.json', 'xss_dalfox.json', 'sqlmap/', 'report.txt']),
        ('ssrf_tester',         RED,    ['ssrf_findings.json', 'ssrf_report.txt']),
        ('cloud_misconfig',     CYAN,   ['findings.json', 'report.txt', '(buckets, services)']),
        ('api_tester',          PURPLE, ['findings.json', 'report.txt', '(JWT, GraphQL, Swagger)']),
        ('idor_hunter',         PURPLE, ['findings.json', 'report.txt', '(critical-first sorted)']),
        ('js_analyzer',         ORANGE, ['findings.json', 'secrets.txt', 'endpoints.txt', 'internals.txt']),
        ('subdomain_monitor',   GREEN,  ['delta.txt', 'subdomains.txt', 'meta.json', 'alerts']),
        ('report_builder',      GREEN,  ['report.html', 'report.md']),
    ]

    col_w = 4.4
    row_h = 0.78
    start_y = 5.85
    for i, (name, color, files) in enumerate(scanners):
        row = i // 3
        col = i % 3
        x = col * col_w + 0.3
        y = start_y - row * row_h * 2.1

        # Card
        for alpha, lw in [(0.07, 8), (0.13, 4)]:
            ax.add_patch(FancyBboxPatch((x, y - row_h * 1.5), col_w - 0.3, row_h * 1.7,
                                        boxstyle='round,pad=0.05',
                                        linewidth=lw, edgecolor=color,
                                        facecolor='none', alpha=alpha))
        ax.add_patch(FancyBboxPatch((x, y - row_h * 1.5), col_w - 0.3, row_h * 1.7,
                                    boxstyle='round,pad=0.05',
                                    linewidth=1.1, edgecolor=color,
                                    facecolor=CARD_BG))

        ax.text(x + (col_w - 0.3) / 2, y - 0.02,
                name, fontsize=9, fontweight='bold',
                ha='center', va='center', color=color,
                fontfamily='monospace')

        file_str = '  ·  '.join(files[:3])
        if len(files) > 3:
            file_str += '  ...'
        ax.text(x + (col_w - 0.3) / 2, y - row_h * 0.85,
                file_str, fontsize=6.8,
                ha='center', va='center', color=GRAY,
                fontfamily='monospace')

    # Severity legend
    sev = [('Critical', RED), ('High', ORANGE), ('Medium', ORANGE),
           ('Low', BLUE), ('Info', GRAY)]
    for idx, (lbl, c) in enumerate(sev):
        bx = 1.0 + idx * 2.5
        ax.add_patch(FancyBboxPatch((bx, 0.15), 0.3, 0.3,
                                    boxstyle='round,pad=0.03',
                                    facecolor=c, edgecolor='none'))
        ax.text(bx + 0.42, 0.30, lbl, fontsize=8.5,
                va='center', color=WHITE, fontfamily='monospace')

    plt.tight_layout(pad=0.4)
    fig.savefig(os.path.join(OUT, 'output_summary.png'), dpi=150,
                bbox_inches='tight', facecolor=DARK_BG)
    plt.close()
    print('[+] output_summary.png')


if __name__ == '__main__':
    gen_banner()
    gen_pipeline()
    gen_architecture()
    gen_radar()
    gen_output_summary()
    print('\nAll images saved to:', OUT)
