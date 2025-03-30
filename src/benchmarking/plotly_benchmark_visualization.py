#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Visualización interactiva de los resultados del benchmark de algoritmos de encriptación con Plotly.
Este script genera gráficos HTML interactivos para comparar el rendimiento de los algoritmos.
"""

import os
import sys
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple

# Directorio donde se guardarán los gráficos
OUTPUT_DIR = "benchmark_results"

# Datos de ejemplo (puedes reemplazar estos con los resultados reales del benchmark)
DATA_SIZES = [100, 1000, 10000, 50000]

# Tiempos de encriptación (segundos)
ENCRYPTION_TIMES = {
    "AES (Simétrico)": [0.000056, 0.000060, 0.000073, 0.000149],
    "RSA (Asimétrico)": [0.000758, None, None, None],
    "Híbrido (RSA+AES)": [0.000566, 0.000738, 0.000847, 0.000662],
    "Caos v3 (Personalizado)": [0.000143, 0.000994, 0.012189, 0.044685],
    "Caos v4 (AES-GCM)": [0.000731, 0.000350, 0.000532, 0.000505]
}

# Tiempos de desencriptación (segundos)
DECRYPTION_TIMES = {
    "AES (Simétrico)": [0.000017, 0.000043, 0.000032, 0.000087],
    "RSA (Asimétrico)": [0.002912, None, None, None],
    "Híbrido (RSA+AES)": [0.004901, 0.002691, 0.002896, 0.002809],
    "Caos v3 (Personalizado)": [0.000097, 0.000802, 0.012378, 0.046275],
    "Caos v4 (AES-GCM)": [0.000294, 0.000280, 0.000475, 0.000456]
}

# Colores para cada algoritmo
ALGORITHM_COLORS = {
    "AES (Simétrico)": "royalblue",
    "RSA (Asimétrico)": "crimson",
    "Híbrido (RSA+AES)": "forestgreen",
    "Caos v3 (Personalizado)": "darkorchid",
    "Caos v4 (AES-GCM)": "darkorange"
}

def create_directory():
    """Crea el directorio para guardar los resultados si no existe."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Directorio creado: {OUTPUT_DIR}")

def create_line_charts():
    """Crea gráficos de líneas interactivos para los tiempos de encriptación y desencriptación."""
    # Preparar figura con subplots
    fig = make_subplots(
        rows=2, 
        cols=1,
        subplot_titles=("Tiempos de Encriptación", "Tiempos de Desencriptación"),
        vertical_spacing=0.15
    )
    
    # Añadir trazos para cada algoritmo - Encriptación
    for algorithm, times in ENCRYPTION_TIMES.items():
        # Filtrar valores None
        valid_indices = [i for i, t in enumerate(times) if t is not None]
        valid_sizes = [DATA_SIZES[i] for i in valid_indices]
        valid_times = [times[i] for i in valid_indices]
        
        fig.add_trace(
            go.Scatter(
                x=valid_sizes, 
                y=valid_times,
                mode="lines+markers",
                name=algorithm,
                line=dict(color=ALGORITHM_COLORS[algorithm], width=3),
                marker=dict(size=8, symbol="circle"),
                hovertemplate="<b>%{y:.8f} s</b> para %{x} bytes<extra></extra>"
            ),
            row=1, col=1
        )
    
    # Añadir trazos para cada algoritmo - Desencriptación
    for algorithm, times in DECRYPTION_TIMES.items():
        # Filtrar valores None
        valid_indices = [i for i, t in enumerate(times) if t is not None]
        valid_sizes = [DATA_SIZES[i] for i in valid_indices]
        valid_times = [times[i] for i in valid_indices]
        
        fig.add_trace(
            go.Scatter(
                x=valid_sizes,
                y=valid_times,
                mode="lines+markers",
                name=algorithm,
                line=dict(color=ALGORITHM_COLORS[algorithm], width=3, dash="dot"),
                marker=dict(size=8, symbol="square"),
                showlegend=False,
                hovertemplate="<b>%{y:.8f} s</b> para %{x} bytes<extra></extra>"
            ),
            row=2, col=1
        )
    
    # Actualizar diseño
    fig.update_layout(
        title=dict(
            text="Comparación de Rendimiento de Algoritmos de Encriptación",
            font=dict(size=24, family="Arial Bold")
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5,
            font=dict(size=14)
        ),
        hovermode="closest",
        template="plotly_white",
        width=1000,
        height=800,
    )
    
    # Actualizar ejes
    fig.update_xaxes(
        title_text="Tamaño de datos (bytes)",
        type="log",
        dtick=1,
        tickfont=dict(size=12),
        gridcolor='lightgray',
        row=1, col=1
    )
    
    fig.update_xaxes(
        title_text="Tamaño de datos (bytes)",
        type="log",
        dtick=1,
        tickfont=dict(size=12),
        gridcolor='lightgray',
        row=2, col=1
    )
    
    fig.update_yaxes(
        title_text="Tiempo (segundos)",
        type="log",
        tickfont=dict(size=12),
        gridcolor='lightgray',
        row=1, col=1
    )
    
    fig.update_yaxes(
        title_text="Tiempo (segundos)",
        type="log",
        tickfont=dict(size=12),
        gridcolor='lightgray',
        row=2, col=1
    )
    
    # Guardar el gráfico como HTML interactivo
    fig.write_html(os.path.join(OUTPUT_DIR, "encryption_benchmark_lines.html"))
    print(f"Gráfico de líneas guardado en: {os.path.join(OUTPUT_DIR, 'encryption_benchmark_lines.html')}")
    
    return fig

def create_bar_charts():
    """Crea gráficos de barras interactivos para comparar algoritmos en cada tamaño de datos."""
    # Crear un gráfico para cada tamaño de datos
    for i, size in enumerate(DATA_SIZES):
        # Preparar datos para este tamaño
        algorithms = []
        enc_times = []
        dec_times = []
        
        for algorithm in ENCRYPTION_TIMES.keys():
            # Solo incluir algoritmos con datos para este tamaño
            if (ENCRYPTION_TIMES[algorithm][i] is not None and 
                DECRYPTION_TIMES[algorithm][i] is not None):
                algorithms.append(algorithm)
                enc_times.append(ENCRYPTION_TIMES[algorithm][i])
                dec_times.append(DECRYPTION_TIMES[algorithm][i])
        
        # Crear figura
        fig = go.Figure()
        
        # Añadir barras para encriptación
        fig.add_trace(go.Bar(
            x=algorithms,
            y=enc_times,
            name="Encriptación",
            marker_color=[ALGORITHM_COLORS[algo] for algo in algorithms],
            opacity=0.8,
            hovertemplate="<b>%{y:.8f} s</b><extra>Encriptación</extra>"
        ))
        
        # Añadir barras para desencriptación
        fig.add_trace(go.Bar(
            x=algorithms,
            y=dec_times,
            name="Desencriptación",
            marker_color=[ALGORITHM_COLORS[algo] for algo in algorithms],
            marker_pattern_shape="/",
            opacity=0.6,
            hovertemplate="<b>%{y:.8f} s</b><extra>Desencriptación</extra>"
        ))
        
        # Actualizar diseño
        fig.update_layout(
            title=dict(
                text=f"Comparación para tamaño de {size} bytes",
                font=dict(size=20, family="Arial Bold")
            ),
            xaxis=dict(
                title="Algoritmo",
                tickangle=-30,
                tickfont=dict(size=14)
            ),
            yaxis=dict(
                title="Tiempo (segundos)",
                type="log",
                tickfont=dict(size=12),
                gridcolor='lightgray'
            ),
            template="plotly_white",
            barmode='group',
            width=800,
            height=600,
            bargap=0.15,
            bargroupgap=0.1,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        # Guardar el gráfico como HTML interactivo
        output_file = os.path.join(OUTPUT_DIR, f"benchmark_size_{size}.html")
        fig.write_html(output_file)
        print(f"Gráfico de barras para {size} bytes guardado en: {output_file}")

def create_heatmap():
    """Crea un mapa de calor para visualizar diferencias relativas de rendimiento."""
    # Preparar datos para el mapa de calor
    enc_data = []
    dec_data = []
    algorithms = list(ENCRYPTION_TIMES.keys())
    
    # Normalizar los tiempos (proporción respecto al más rápido)
    for i, size in enumerate(DATA_SIZES):
        # Encriptación
        valid_times = [ENCRYPTION_TIMES[algo][i] for algo in algorithms 
                      if ENCRYPTION_TIMES[algo][i] is not None]
        if valid_times:
            min_time = min(valid_times)
            row = []
            for algo in algorithms:
                if ENCRYPTION_TIMES[algo][i] is not None:
                    # Cuántas veces más lento que el mejor
                    ratio = ENCRYPTION_TIMES[algo][i] / min_time
                    row.append(ratio)
                else:
                    row.append(None)
            enc_data.append(row)
        
        # Desencriptación
        valid_times = [DECRYPTION_TIMES[algo][i] for algo in algorithms 
                      if DECRYPTION_TIMES[algo][i] is not None]
        if valid_times:
            min_time = min(valid_times)
            row = []
            for algo in algorithms:
                if DECRYPTION_TIMES[algo][i] is not None:
                    # Cuántas veces más lento que el mejor
                    ratio = DECRYPTION_TIMES[algo][i] / min_time
                    row.append(ratio)
                else:
                    row.append(None)
            dec_data.append(row)
    
    # Crear figura con subplots
    fig = make_subplots(
        rows=1, 
        cols=2,
        subplot_titles=("Encriptación (x veces más lento que el mejor)", 
                        "Desencriptación (x veces más lento que el mejor)"),
        horizontal_spacing=0.12
    )
    
    # Colorscale para el mapa de calor (verde=rápido, rojo=lento)
    colorscale = [
        [0, "green"],
        [0.25, "yellowgreen"],
        [0.5, "yellow"],
        [0.75, "orange"],
        [1, "red"]
    ]
    
    # Añadir mapa de calor para encriptación
    fig.add_trace(
        go.Heatmap(
            z=enc_data,
            x=algorithms,
            y=[f"{size} bytes" for size in DATA_SIZES[:len(enc_data)]],
            colorscale=colorscale,
            showscale=True,
            colorbar=dict(title="x veces<br>más lento", x=0.46),
            hovertemplate="<b>%{z:.2f}x</b> más lento que el mejor<extra>%{x}, %{y}</extra>",
            zmin=1,
            zmax=25  # Limitar para mejor visualización
        ),
        row=1, col=1
    )
    
    # Añadir mapa de calor para desencriptación
    fig.add_trace(
        go.Heatmap(
            z=dec_data,
            x=algorithms,
            y=[f"{size} bytes" for size in DATA_SIZES[:len(dec_data)]],
            colorscale=colorscale,
            showscale=True,
            colorbar=dict(title="x veces<br>más lento", x=1.02),
            hovertemplate="<b>%{z:.2f}x</b> más lento que el mejor<extra>%{x}, %{y}</extra>",
            zmin=1,
            zmax=25  # Limitar para mejor visualización
        ),
        row=1, col=2
    )
    
    # Actualizar diseño
    fig.update_layout(
        title=dict(
            text="Comparativa de Eficiencia Relativa",
            font=dict(size=24, family="Arial Bold")
        ),
        width=1200,
        height=500,
        template="plotly_white"
    )
    
    # Actualizar ejes
    for i in range(1, 3):
        fig.update_xaxes(
            tickangle=-30,
            tickfont=dict(size=12),
            row=1, col=i
        )
        
        fig.update_yaxes(
            tickfont=dict(size=12),
            row=1, col=i
        )
    
    # Guardar el gráfico como HTML interactivo
    output_file = os.path.join(OUTPUT_DIR, "relative_performance_heatmap.html")
    fig.write_html(output_file)
    print(f"Mapa de calor guardado en: {output_file}")
    
    return fig

def create_radar_chart():
    """Crea un gráfico de radar para comparar características de cada algoritmo."""
    # Categorías para el gráfico radar
    categories = [
        "Velocidad de encriptación", 
        "Velocidad de desencriptación",
        "Seguridad",
        "Manejabilidad de datos grandes",
        "Resistencia a ataques"
    ]
    
    # Puntuaciones para cada algoritmo (escala 0-10)
    # Estos valores son subjetivos para ilustrar las diferencias
    scores = {
        "AES (Simétrico)": [9.5, 9.5, 8, 9, 8],
        "RSA (Asimétrico)": [5, 3, 9, 2, 9],
        "Híbrido (RSA+AES)": [8, 7, 9.5, 8.5, 9.5],
        "Caos v3 (Personalizado)": [6, 6, 5, 5, 4],
        "Caos v4 (AES-GCM)": [8.5, 8.5, 9, 8.5, 9]
    }
    
    # Crear figura
    fig = go.Figure()
    
    # Añadir trazos para cada algoritmo
    for algorithm, score in scores.items():
        # Cerrar el polígono repitiendo el primer valor
        values = score + [score[0]]
        theta = categories + [categories[0]]
        
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=theta,
            name=algorithm,
            fill='toself',
            line=dict(color=ALGORITHM_COLORS[algorithm], width=3),
            opacity=0.6
        ))
    
    # Actualizar diseño
    fig.update_layout(
        title=dict(
            text="Comparación de Características de los Algoritmos",
            font=dict(size=24, family="Arial Bold")
        ),
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.1,
            xanchor="center",
            x=0.5
        ),
        width=800,
        height=700,
        template="plotly_white"
    )
    
    # Guardar el gráfico como HTML interactivo
    output_file = os.path.join(OUTPUT_DIR, "algorithm_characteristics_radar.html")
    fig.write_html(output_file)
    print(f"Gráfico radar guardado en: {output_file}")
    
    return fig

def create_dashboard():
    """Crea un dashboard HTML que incluye todos los gráficos."""
    # Crear los gráficos individuales
    line_fig = create_line_charts()
    heatmap_fig = create_heatmap()
    radar_fig = create_radar_chart()
    
    # Generar los gráficos de barras
    create_bar_charts()
    
    # Cabecera HTML
    html_head = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Dashboard de Benchmark de Encriptación</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                border-radius: 5px;
            }
            h1 {
                color: #2c3e50;
                text-align: center;
                padding-bottom: 10px;
                border-bottom: 2px solid #ecf0f1;
            }
            h2 {
                color: #3498db;
                margin-top: 30px;
            }
            .plot-container {
                margin: 20px 0;
                padding: 15px;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0,0,0,0.05);
            }
            .row {
                display: flex;
                flex-wrap: wrap;
                margin: 0 -10px;
            }
            .col {
                flex: 1;
                padding: 0 10px;
                min-width: 300px;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                font-size: 0.9em;
                color: #7f8c8d;
            }
            .conclusion {
                background-color: #f8f9fa;
                padding: 15px;
                border-left: 4px solid #3498db;
                margin: a0px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Dashboard de Benchmark de Algoritmos de Encriptación</h1>
            
            <div class="conclusion">
                <h3>Conclusiones Principales:</h3>
                <ul>
                    <li>El algoritmo AES es el más rápido para operaciones simétricas.</li>
                    <li>RSA es significativamente más lento, especialmente en desencriptación.</li>
                    <li>El enfoque híbrido (RSA+AES) ofrece un buen equilibrio entre seguridad y rendimiento.</li>
                    <li>CAOS v4 (AES-GCM) supera significativamente a CAOS v3 en rendimiento y seguridad.</li>
                    <li>Para grandes volúmenes de datos, CAOS v4 es competitivo con AES puro, añadiendo autenticación.</li>
                </ul>
            </div>
    """
    
    # Sección de gráficos
    html_plots = """
            <h2>Rendimiento por Tamaño de Datos</h2>
            <div class="plot-container">
                <iframe src="encryption_benchmark_lines.html" width="100%" height="800" frameborder="0"></iframe>
            </div>
            
            <h2>Eficiencia Relativa (Comparado con el Mejor)</h2>
            <div class="plot-container">
                <iframe src="relative_performance_heatmap.html" width="100%" height="500" frameborder="0"></iframe>
            </div>
            
            <div class="row">
                <div class="col">
                    <h2>Características de los Algoritmos</h2>
                    <div class="plot-container">
                        <iframe src="algorithm_characteristics_radar.html" width="100%" height="700" frameborder="0"></iframe>
                    </div>
                </div>
                <div class="col">
                    <h2>Análisis Detallado</h2>
                    <div class="plot-container">
                        <h3>Comparación por Tamaño</h3>
                        <p>Examina el rendimiento para cada tamaño de datos:</p>
                        <ul>
    """
    
    # Enlaces a los gráficos de barras
    for size in DATA_SIZES:
        html_plots += f'<li><a href="benchmark_size_{size}.html" target="_blank">Datos de {size} bytes</a></li>\n'
    
    html_plots += """
                        </ul>
                    </div>
                </div>
            </div>
    """
    
    # Pie de página
    html_foot = """
            <div class="footer">
                <p>Generado para el análisis de algoritmos de encriptación © 2023</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Combinar todo el HTML
    dashboard_html = html_head + html_plots + html_foot
    
    # Guardar el dashboard
    output_file = os.path.join(OUTPUT_DIR, "encryption_benchmark_dashboard.html")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(dashboard_html)
    
    print(f"Dashboard guardado en: {output_file}")

def main():
    """Función principal."""
    print("=" * 80)
    print("GENERACIÓN DE VISUALIZACIONES INTERACTIVAS DE BENCHMARK")
    print("=" * 80)
    
    # Crear directorio para resultados
    create_directory()
    
    # Generar todas las visualizaciones
    create_line_charts()
    create_bar_charts()
    create_heatmap()
    create_radar_chart()
    
    # Crear dashboard
    create_dashboard()
    
    print("\nVisualización completada. Abra los archivos HTML en su navegador para ver los resultados.")
    print(f"Dashboard principal: {os.path.join(OUTPUT_DIR, 'encryption_benchmark_dashboard.html')}")

if __name__ == "__main__":
    main() 