import streamlit as st
import pandas as pd
import re
import requests
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

# --- FUNCIÓN ACTUALIZADA: OBTENER APPLE ID (Formato idXXXXXXXXX) ---
def get_apple_store_id(app_name):
    if not app_name or str(app_name).strip().lower() in ['sin id', 'nan', 'none', '']:
        return "N/A"
    try:
        url = f"https://itunes.apple.com/search?term={app_name}&entity=software&limit=1"
        response = requests.get(url, timeout=5)
        data = response.json()
        if data['resultCount'] > 0:
            track_id = data['results'][0].get('trackId')
            if track_id:
                return f"id{track_id}"
        return "No encontrado"
    except Exception:
        return "Error de conexión"

# Función utilitaria compartida para buscar columnas
def find_col(df, possible_names):
    for col in df.columns:
        if col.strip().lower() in possible_names:
            return col
    return None

# Crear las CUATRO pestañas principales
tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 Analizador de URLs", 
    "🌍 Extractor Masivo de IPs", 
    "📱 Analizador Munimob (af_ip)",
    "🔀 Analizador Cruzado Multidimensional"
])

# ==========================================
# PESTAÑA 1: ANALIZADOR DE URLS Y TOKENS
# ==========================================
with tab1:
    st.header("Analizador de URLs (Versión Simplificada)")
    uploaded_file = st.file_uploader("Sube un (1) archivo CSV para analizar URLs", type=["csv"], key="url_uploader")

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            
            st.subheader("1. Tokens Únicos (Postback URL)")
            col_postback = find_col(df, ["postback url"])
            
            if col_postback:
                token_pattern = re.compile(r'(\{.*?\}|\[.*?\]|<.*?>)')
                all_tokens = []
                urls_pb = df[col_postback].dropna().astype(str)
                for url in urls_pb:
                    all_tokens.extend(token_pattern.findall(url))
                
                if all_tokens:
                    token_counts = Counter(all_tokens)
                    df_tokens = pd.DataFrame(token_counts.items(), columns=["Token", "Frecuencia"]).sort_values(by="Frecuencia", ascending=False)
                    
                    c1, c2 = st.columns([1, 2])
                    with c1:
                        st.dataframe(df_tokens[["Token"]].reset_index(drop=True), use_container_width=True)
                    with c2:
                        st.bar_chart(df_tokens.set_index("Token"))
                else:
                    st.info("No se encontraron tokens.")
            else:
                st.warning("Columna 'Postback Url' no encontrada.")

            st.divider()
            st.subheader("2. Parámetros Únicos Detectados (Original URL)")
            col_original = find_col(df, ["original url"])
            
            if col_original:
                all_params_pairs = []
                param_names = set()
                urls_orig = df[col_original].dropna().astype(str)
                
                for url in urls_orig:
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values:
                            all_params_pairs.append({"Parámetro": key, "Valor": val})
                
                if param_names:
                    df_unique_names = pd.DataFrame(sorted(list(param_names)), columns=["Nombre del Parámetro"])
                    df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                    
                    st.write("**Nombres de parámetros encontrados (Sin duplicados):**")
                    st.dataframe(df_unique_names, use_container_width=True)
                    
                    st.write("**Combinaciones de Valor únicas:**")
                    st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)

                    st.divider()
                    st.subheader("3. Filtro Específico AppsFlyer")
                    col_af1, col_af2 = st.columns(2)
                    
                    with col_af1:
                        st.write("**af_xplatform_vt_lookback**")
                        lookback_vals = df_unique_pairs[df_unique_pairs["Parámetro"] == "af_xplatform_vt_lookback"]["Valor"].unique()
                        if len(lookback_vals) > 0:
                            st.table(pd.DataFrame(lookback_vals, columns=["Valores Únicos"]))
                        else:
                            st.info("No detectado.")
                            
                    with col_af2:
                        st.write("**af_pmod_priority**")
                        priority_vals = df_unique_pairs[df_unique_pairs["Parámetro"] == "af_pmod_priority"]["Valor"].unique()
                        if len(priority_vals) > 0:
                            st.table(pd.DataFrame(priority_vals, columns=["Valores Únicos"]))
                        else:
                            st.info("No detectado.")
                else:
                    st.info("No se detectaron parámetros en la Original URL.")
            else:
                st.warning("Columna 'Original URL' no encontrada.")
        except Exception as e:
            st.error(f"Error procesando el archivo: {e}")

# ==========================================
# PESTAÑA 2: EXTRACTOR MASIVO DE IPS + ADSETS
# ==========================================
with tab2:
    st.header("Extractor y Agrupador de IPs y Adsets")
    st.markdown("Sube múltiples CSVs para unificar datos y analizar Adsets por País.")
    
    uploaded_csvs = st.file_uploader("Arrastra aquí todos tus CSVs", type=["csv"], accept_multiple_files=True, key="multi_csv_uploader")
    
    if uploaded_csvs:
        try:
            dataframes = [pd.read_csv(file) for file in uploaded_csvs]
            df_master = pd.concat(dataframes, ignore_index=True)
            st.success(f"✅ Se han fusionado {len(uploaded_csvs)} archivos con un total de {len(df_master)} filas.")
            
            # Buscador de columnas
            col_ip = find_col(df_master, ['ip', 'ip address', 'ip_address'])
            col_os = find_col(df_master, ['os', 'platform', 'operating system'])
            col_country = find_col(df_master, ['country', 'country code', 'country_code', 'país', 'pais'])
            col_adset = find_col(df_master, ['adset_id', 'adset id', 'adset_name', 'adset name', 'ad group id', 'adgroup_id'])

            # --- SECCIÓN ADSETS POR PAÍS ---
            st.divider()
            st.subheader("🎯 Adset IDs separados por País")
            
            if col_adset and col_country:
                adset_country_df = df_master.groupby([col_country, col_adset]).size().reset_index(name='Frecuencia')
                adset_country_df = adset_country_df.sort_values(by=[col_country, 'Frecuencia'], ascending=[True, False]).reset_index(drop=True)
                
                st.write(f"Se han detectado **{len(adset_country_df[col_adset].unique())}** Adsets en **{len(adset_country_df[col_country].unique())}** países.")
                st.dataframe(adset_country_df, use_container_width=True)
                
                # Descarga de Adsets
                csv_adsets = adset_country_df.to_csv(index=False).encode('utf-8')
                st.download_button(label="⬇️ Descargar Adsets por País (CSV)", data=csv_adsets, file_name="adsets_por_pais.csv", mime="text/csv")

                # --- SECCIÓN: BÚSQUEDA DE APPLE IDs ---
                st.markdown("### 🔍 Obtener Apple IDs Oficiales (idXXXXXXXXX)")
                st.info("Haz clic abajo para buscar el ID numérico de la tienda de Apple para cada Adset Name.")
                
                if st.button("Buscar Apple IDs en App Store"):
                    unique_apps = [app for app in adset_country_df[col_adset].unique() if str(app).strip().lower() not in ['sin id', 'nan', 'none', '']]
                    
                    mapping = {}
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    for i, app_name in enumerate(unique_apps):
                        status_text.text(f"Consultando Apple ID para: {app_name}...")
                        mapping[app_name] = get_apple_store_id(app_name)
                        progress_bar.progress((i + 1) / len(unique_apps))
                        
                    status_text.text("✅ Búsqueda de Apple IDs completada.")
                    
                    adset_enriched_df = adset_country_df.copy()
                    adset_enriched_df['Apple ID'] = adset_enriched_df[col_adset].map(mapping).fillna('N/A')
                    
                    st.dataframe(adset_enriched_df, use_container_width=True)
                    
                    csv_apple = adset_enriched_df.to_csv(index=False).encode('utf-8')
                    st.download_button(label="⬇️ Descargar Reporte con Apple IDs", data=csv_apple, file_name="adsets_con_apple_ids.csv", mime="text/csv")
            
            elif col_adset:
                st.info("ℹ️ Se encontró la columna Adset pero no la de País. Mostrando frecuencias globales:")
                adset_global = df_master[col_adset].value_counts().reset_index()
                adset_global.columns = [col_adset, 'Frecuencia']
                st.dataframe(adset_global, use_container_width=True)
            else:
                st.warning("⚠️ No se encontró la columna de Adset ID en los archivos.")

            # --- SECCIÓN IPs ---
            st.divider()
            if col_ip and col_os and col_country:
                df_clean = df_master.dropna(subset=[col_ip, col_os, col_country]).copy()
                st.subheader("📊 IPs Únicas por País/OS")
                grouped = df_clean.groupby([col_country, col_os])[col_ip].unique().reset_index()
                grouped['Total IPs Únicas'] = grouped[col_ip].apply(len)
                grouped['Lista de IPs'] = grouped[col_ip].apply(lambda ips: ", ".join(map(str, ips)))
                
                df_ips_unicas = grouped[[col_country, col_os, 'Total IPs Únicas', 'Lista de IPs']]
                st.dataframe(df_ips_unicas, use_container_width=True)
                
                csv_ips_unicas = df_ips_unicas.to_csv(index=False).encode('utf-8')
                st.download_button(label="⬇️ Descargar IPs Únicas por País/OS (CSV)", data=csv_ips_unicas, file_name="ips_unicas_pais_os.csv", mime="text/csv")
                
                st.subheader("📊 Frecuencia de todas las IPs")
                ip_counts = df_clean.groupby([col_country, col_os, col_ip]).size().reset_index(name='Repeticiones')
                all_ips_counted = ip_counts.sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                st.dataframe(all_ips_counted, use_container_width=True)
                
                st.divider()
                st.subheader("🔍 Investigador de IP")
                search_ip = st.text_input("Introduce la IP a buscar:")
                if search_ip:
                    ip_details = df_master[df_master[col_ip].astype(str).str.strip() == search_ip.strip()]
                    if not ip_details.empty:
                        st.dataframe(ip_details, use_container_width=True)
                    else:
                        st.warning("⚠️ No se encontró la IP.")
        except Exception as e:
            st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 3: ANALIZADOR MUNIMOB
# ==========================================
with tab3:
    st.header("📱 Analizador Munimob (Extracción de af_ip)")
    uploaded_munimob = st.file_uploader("Sube tus CSVs de Munimob", type=["csv"], accept_multiple_files=True, key="munimob_uploader")
    
    if uploaded_munimob:
        try:
            df_munimob = pd.concat([pd.read_csv(f) for f in uploaded_munimob], ignore_index=True)
            st.success(f"✅ Se han procesado {len(df_munimob)} filas.")
            col_orig = find_col(df_munimob, ['original url', 'original_url'])
            
            if col_orig:
                all_params_pairs = []
                param_names = set()
                extracted_af_ips = []
                
                for url in df_munimob[col_orig].fillna('').astype(str):
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values:
                            all_params_pairs.append({"Parámetro": key, "Valor": val})
                    extracted_af_ips.append(params['af_ip'][0] if 'af_ip' in params and len(params['af_ip']) > 0 else None)
                
                df_munimob['AF_IP_Extraida'] = extracted_af_ips
                
                st.subheader("1. Parámetros Únicos de la URL")
                df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)

                df_clean_ips = df_munimob.dropna(subset=['AF_IP_Extraida']).copy()
                if not df_clean_ips.empty:
                    st.divider()
                    st.subheader("2. Lista limpia de `af_ip` únicas")
                    unique_af_ips = df_clean_ips['AF_IP_Extraida'].unique()
                    st.dataframe(pd.DataFrame(unique_af_ips, columns=['af_ip']), use_container_width=True)
                    
                    st.divider()
                    st.subheader("3. Análisis de Fraude sobre `af_ip` (>= 5)")
                    col_os_m = find_col(df_clean_ips, ['os', 'platform', 'operating system'])
                    col_country_m = find_col(df_clean_ips, ['country', 'country code', 'país', 'pais'])
                    
                    groupby_cols = []
                    if col_country_m: groupby_cols.append(col_country_m)
                    if col_os_m: groupby_cols.append(col_os_m)
                    groupby_cols.append('AF_IP_Extraida')
                    
                    ip_counts = df_clean_ips.groupby(groupby_cols).size().reset_index(name='Repeticiones')
                    suspicious_ips = ip_counts[ip_counts['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    
                    if not suspicious_ips.empty:
                        st.dataframe(suspicious_ips, use_container_width=True)
                        st.download_button("⬇️ Descargar Alertas af_ip", data=suspicious_ips.to_csv(index=False).encode('utf-8'), file_name="alertas_af_ip.csv", mime="text/csv")
                    else:
                        st.success("✅ No hay IPs repetidas 5+ veces.")
                
                st.divider()
                st.subheader("🔍 4. Investigador Forense (`af_ip`)")
                search_af_ip = st.text_input("Introduce la af_ip a buscar:")
                if search_af_ip:
                    ip_details = df_munimob[df_munimob['AF_IP_Extraida'].astype(str) == search_af_ip.strip()]
                    if not ip_details.empty:
                        display_df = ip_details.drop(columns=['AF_IP_Extraida'])
                        st.success(f"✅ Se encontraron {len(ip_details)} registros.")
                        st.dataframe(display_df, use_container_width=True)
                        st.download_button(f"⬇️ Descargar historial", data=display_df.to_csv(index=False).encode('utf-8'), file_name=f"reporte_{search_af_ip}.csv", mime="text/csv")

        except Exception as e:
            st.error(f"Error en Munimob: {e}")

# ==========================================
# PESTAÑA 4: ANALIZADOR CRUZADO MULTIDIMENSIONAL
# ==========================================
with tab4:
    st.header("🔀 Analizador de Frecuencias y Cruces de Datos")
    st.markdown("Esta herramienta lee **todas las columnas** de tus CSVs, te muestra qué valores se repiten en cada una y te permite cruzarlas para encontrar patrones ocultos.")
    
    uploaded_cross = st.file_uploader("Sube tus CSVs para análisis cruzado", type=["csv"], accept_multiple_files=True, key="cross_uploader")
    
    if uploaded_cross:
        try:
            df_cross = pd.concat([pd.read_csv(f) for f in uploaded_cross], ignore_index=True)
            st.success(f"✅ Se han procesado {len(df_cross)} registros para análisis cruzado.")
            
            # --- PARTE 1: FRECUENCIAS INDIVIDUALES POR COLUMNA ---
            st.subheader("1. Frecuencia individual por columna")
            st.markdown("Despliega cualquier columna para ver cuáles son sus valores más repetidos (ordenados de mayor a menor).")
            
            # Creamos 3 columnas en la interfaz para que los desplegables se vean ordenados y no ocupen tanto espacio vertical
            c1, c2, c3 = st.columns(3)
            
            for i, col in enumerate(df_cross.columns):
                # Repartir los expanders entre las 3 columnas de la pantalla
                target_col = [c1, c2, c3][i % 3]
                
                with target_col:
                    with st.expander(f"📊 {col}"):
                        val_counts = df_cross[col].value_counts().reset_index()
                        val_counts.columns = ['Valor', 'Repeticiones']
                        st.dataframe(val_counts, use_container_width=True)
            
            # --- PARTE 2: CRUCE DE DATOS ---
            st.divider()
            st.subheader("2. Analizador Cruzado (Combinaciones)")
            st.markdown("Selecciona **dos o más columnas** para ver cuántas veces se repite cada combinación exacta.")
            
            cols_to_cross = st.multiselect("Selecciona las columnas a cruzar (ej. OS + País + Adset_Name):", df_cross.columns)
            
            if cols_to_cross:
                # Crear tabla de combinaciones
                df_crossed = df_cross.groupby(cols_to_cross).size().reset_index(name='Repeticiones')
                df_crossed = df_crossed.sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                
                st.write(f"Se encontraron **{len(df_crossed)}** combinaciones únicas.")
                st.dataframe(df_crossed, use_container_width=True)
                
                # --- PARTE 3: BUSCADOR DENTRO DEL CRUCE ---
                st.markdown("### 🔍 Filtrar Combinaciones")
                st.markdown("Escribe un valor exacto para filtrar la tabla cruzada superior (ej. buscar un ID de Adset o un País específico).")
                
                search_cross = st.text_input("Buscar valor en cualquiera de las columnas cruzadas:")
                
                if search_cross:
                    # Aplicamos una máscara que busca el texto en cualquiera de las columnas seleccionadas
                    mask = df_crossed[cols_to_cross].astype(str).apply(lambda x: x.str.contains(search_cross.strip(), case=False, na=False)).any(axis=1)
                    df_filtered = df_crossed[mask]
                    
                    if not df_filtered.empty:
                        st.success(f"✅ Se encontraron {len(df_filtered)} combinaciones que incluyen el valor '{search_cross}'.")
                        st.dataframe(df_filtered, use_container_width=True)
                        
                        csv_filtered = df_filtered.to_csv(index=False).encode('utf-8')
                        st.download_button("⬇️ Descargar Filtrado", data=csv_filtered, file_name=f"cruce_filtrado_{search_cross}.csv", mime="text/csv")
                    else:
                        st.warning(f"⚠️ No se encontró el valor '{search_cross}' en las combinaciones generadas.")
                        
        except Exception as e:
            st.error(f"Error al procesar el análisis cruzado: {e}")
