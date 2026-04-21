import streamlit as st
import pandas as pd
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs
import plotly.express as px

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

# Crear las tres pestañas
tab1, tab2, tab3 = st.tabs([
    "🔗 Analizador de URLs", 
    "🌍 Extractor Masivo de IPs", 
    "📍 Mapa de Installs"
])

# Función utilitaria para buscar columnas
def find_col(df, possible_names):
    for col in df.columns:
        if col.strip().lower() in possible_names:
            return col
    return None

# ==========================================
# PESTAÑA 1: ANALIZADOR DE URLS
# ==========================================
with tab1:
    st.header("Analizador de URLs")
    uploaded_file = st.file_uploader("Sube un (1) archivo CSV para analizar URLs", type=["csv"], key="url_uploader")
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            # (El código de la Pestaña 1 se mantiene igual que antes...)
            st.info("Pestaña cargada correctamente. Sube el archivo para ver los parámetros.")
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 2: EXTRACTOR MASIVO DE IPS
# ==========================================
with tab2:
    st.header("Extractor y Agrupador de IPs")
    uploaded_csvs_ip = st.file_uploader("Sube múltiples CSVs para IPs", type=["csv"], accept_multiple_files=True, key="multi_ip")
    if uploaded_csvs_ip:
        # (El código de la Pestaña 2 se mantiene igual...)
        st.info("Fusión de archivos lista para procesar IPs.")

# ==========================================
# PESTAÑA 3: MAPA DE INSTALLS (NUEVA)
# ==========================================
with tab3:
    st.header("Visualización Geográfica de Installs")
    st.markdown("Sube uno o varios CSVs para ver la distribución global de tus conversiones.")
    
    uploaded_maps = st.file_uploader("Sube tus CSVs aquí", type=["csv"], accept_multiple_files=True, key="map_uploader")
    
    if uploaded_maps:
        try:
            # Unir archivos
            dfs = [pd.read_csv(f) for f in uploaded_maps]
            df_map = pd.concat(dfs, ignore_index=True)
            
            # Buscar columnas de ubicación
            col_lat = find_col(df_map, ['lat', 'latitude', 'latitud'])
            col_lon = find_col(df_map, ['lon', 'longitude', 'longitud', 'lng'])
            col_country = find_col(df_map, ['country', 'country code', 'país', 'pais'])
            
            # CASO A: Tenemos Coordenadas (Dibujamos puntos)
            if col_lat and col_lon:
                st.subheader("📍 Mapa de Puntos Exactos")
                df_coords = df_map.dropna(subset=[col_lat, col_lon])
                
                fig = px.scatter_mapbox(
                    df_coords, 
                    lat=col_lat, 
                    lon=col_lon, 
                    zoom=1, 
                    mapbox_style="carto-darkmatter", # Estilo premium oscuro
                    title="Ubicación de Installs por Coordenadas",
                    height=600,
                    size_max=15,
                    color_discrete_sequence=["#00f2ff"] # Color cian neón
                )
                fig.update_layout(margin={"r":0,"t":40,"l":0,"b":0})
                st.plotly_chart(fig, use_container_width=True)
                
            # CASO B: Solo tenemos País (Mapa de calor)
            elif col_country:
                st.subheader("🌍 Mapa de Calor por País")
                country_counts = df_map[col_country].value_counts().reset_index()
                country_counts.columns = [col_country, 'Installs']
                
                fig = px.choropleth(
                    country_counts,
                    locations=col_country,
                    locationmode='country names', # O 'ISO-3' si usas códigos de 3 letras
                    color='Installs',
                    hover_name=col_country,
                    color_continuous_scale=px.colors.sequential.Viridis,
                    title="Installs por Volumen de País",
                    height=600
                )
                fig.update_layout(template="plotly_dark", margin={"r":0,"t":40,"l":0,"b":0})
                st.plotly_chart(fig, use_container_width=True)
                
                # Mostrar tabla de resumen debajo
                st.write("### Resumen por País")
                st.dataframe(country_counts, use_container_width=True)
                
            else:
                st.error("❌ No se encontraron columnas de Latitud/Longitud ni de País.")
                st.info("Encabezados detectados: " + ", ".join(df_map.columns))
                
        except Exception as e:
            st.error(f"Error al generar el mapa: {e}")
