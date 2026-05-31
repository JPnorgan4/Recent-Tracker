# RecentTracker v1.0

Herramienta forense ética para **Windows 11** que detecta programas, archivos
y directorios instalados/creados dentro de una ventana de tiempo configurable.

---

## Requisitos

- Python 3.10+
- Windows 11 (o Windows 10)
- Recomendado: ejecutar como **Administrador** (Prefetch + claves de registro
  protegidas requieren privilegios elevados)

```bash
pip install -r requirements.txt
```

| Paquete    | Rol                                              | Obligatorio |
|------------|--------------------------------------------------|-------------|
| `rich`     | Tablas con color en consola                     | No          |
| `pywin32`  | Leer Event Log (eventos MSI instalador)          | No          |

---

## Uso rápido

```bash
# Último minuto
python recent_tracker.py --preset 1m

# Última hora
python recent_tracker.py --preset 1h

# Últimas 6 horas
python recent_tracker.py --hours 6

# Últimos 3 días, solo programas y archivos
python recent_tracker.py --days 3 --category PROGRAM FILE

# Última semana, exportar JSON + CSV
python recent_tracker.py --weeks 1 --export both --output informe_semana

# 30 minutos, rutas adicionales, solo extensiones críticas
python recent_tracker.py --minutes 30 --scan-paths C:\Downloads C:\Temp --high-interest-only

# Sin escaneo de sistema de archivos (más rápido)
python recent_tracker.py --preset 1d --no-fs
```

---

## Scanners incluidos

| Scanner        | Fuente                                         | Requiere Admin |
|----------------|------------------------------------------------|----------------|
| **Registry**   | HKLM/HKCU Uninstall keys                       | Parcial        |
| **Filesystem** | Directorios sistema + usuario (st_ctime)       | No             |
| **Event Log**  | Application Log, EventID 1033/11707 (MsiInstaller) | No         |
| **AppX**       | `Get-AppxPackage` via PowerShell               | No             |
| **Prefetch**   | `C:\Windows\Prefetch` (*.pf mtime)             | **Sí**         |

---

## Opciones completas

```
Time window (exactly one required):
  --preset {1m,1h,1d,1w}       Preset rápido
  --minutes N                  Últimos N minutos
  --hours N                    Últimas N horas
  --days N                     Últimos N días
  --weeks N                    Últimas N semanas

Scanner control:
  --no-registry                Omitir registro
  --no-fs                      Omitir sistema de archivos
  --no-events                  Omitir Event Log
  --no-appx                    Omitir AppX/Store
  --no-prefetch                Omitir Prefetch
  --scan-paths PATH [PATH ...] Directorios extra para escaneo FS
  --max-depth N                Profundidad máxima recursión (def: 6)
  --workers N                  Threads paralelos (def: 4)

Filtering:
  --category CAT [CAT ...]     Filtrar por categoría:
                               PROGRAM FILE DIRECTORY EVENT APPX PREFETCH
  --high-interest-only         Solo archivos con extensiones de alto interés
                               (.exe .dll .sys .ps1 .bat .msi ...)

Output:
  --export {json,csv,both}     Exportar resultados
  --output BASENAME            Nombre base del fichero exportado
  --plain                      Salida texto plano (sin rich)
  --quiet / -q                 Suprimir consola (usar con --export)
  --verbose / -v               Logging debug
```

---

## Categorías de salida

| Categoría   | Descripción                                       |
|-------------|---------------------------------------------------|
| `PROGRAM`   | Programas detectados en registro de desinstalación |
| `FILE`      | Ficheros creados en directorios monitorizados     |
| `DIRECTORY` | Directorios creados en rutas monitorizadas        |
| `EVENT`     | Eventos MSI del Log de aplicaciones de Windows   |
| `APPX`      | Paquetes UWP/MSIX (Microsoft Store)              |
| `PREFETCH`  | Ejecutables con primer run reciente               |

---

## Extensiones de alto interés (FILE)

`.exe` `.dll` `.sys` `.bat` `.cmd` `.ps1` `.vbs` `.js` `.msi`
`.cab` `.inf` `.reg` `.scr` `.jar` `.py` `.sh` `.com` `.hta`

---

## Escalabilidad futura

El diseño plugin-based permite añadir nuevos scanners heredando `BaseScanner`:

```python
class MiScanner(BaseScanner):
    name = "Mi Scanner"
    def scan(self) -> List[Finding]:
        ...
        return [Finding(category="FILE", name="...", path="...", timestamp=...)]
```

Añade la instancia a la lista `scanners` en `main()` y está listo.

---

## Uso ético

Esta herramienta está diseñada para:
- Auditorías de seguridad autorizadas
- Bug bounty sobre sistemas propios o con permiso escrito
- Análisis forense en entornos corporativos propios
- Investigación de seguridad en laboratorio

**No usar en sistemas sin autorización expresa.**
