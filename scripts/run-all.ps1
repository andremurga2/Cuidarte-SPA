$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force logs | Out-Null
$resultados = @()
function Paso($nombre, [scriptblock]$accion) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $global:LASTEXITCODE = 0
  & $accion *> ("logs\" + ($nombre -replace '\W','_') + ".txt")
  $ok = ($LASTEXITCODE -eq 0)
  $sw.Stop()
  $script:resultados += [pscustomobject]@{ Control = $nombre; Estado = $(if ($ok) {"OK"} else {"FALLA"}); Segundos = [math]::Round($sw.Elapsed.TotalSeconds, 1) }
}
$env:API_URL = "http://localhost:4444"
Paso "npm audit (SCA)"     { Push-Location BACKEND; npm audit --omit=dev --audit-level=high; Pop-Location }
Paso "Jest + Supertest"    { Push-Location BACKEND; npm test; Pop-Location }
Paso "k6 carga"            { Get-Content BACKEND\k6.js -Raw | docker run --rm -i -e API=http://host.docker.internal:4444 grafana/k6 run - }
Paso "Trivy backend"       { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 cuidarteplus-ev-cuidarteplus-backend-ev }
Paso "Trivy frontend"      { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 cuidarteplus-ev-cuidarteplus-frontend-ev }
Paso "Gitleaks (secretos)" { docker run --rm -v "${PWD}:/repo" zricethezav/gitleaks:latest detect --source /repo --no-git }
$resultados | Format-Table -AutoSize
"Total: {0} s" -f (($resultados | Measure-Object Segundos -Sum).Sum)