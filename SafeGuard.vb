Imports Newtonsoft.Json
Imports SafeGuard

Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading.Tasks


Namespace SafeGuard
    Partial Public Class AttackLog
        Public Property Id As Long
        Public Property AttkIp As String
        Public Property AttkPort As Integer
        Public Property AttkTime As Integer
        Public Property AttkMethod As String
        Public Property Client As String
        Public Property ClientIp As String
        Public Property ProgramId As Long
        Public Property Timestamp As System.DateTime
        Public Property ManuallyStopped As Boolean
        Public Property TimeInMS As Long
    End Class

    Partial Public Class MethodStats
        Public Property Method As String
        Public Property Count As Integer
    End Class

    Friend Module SafeGuardAttackInfo
        Friend RunningAttacks As List(Of AttackLog)
        Friend PastAttacks As List(Of AttackLog)
        Friend MethodInformation As List(Of MethodStats)

        Function GetRunningAttacks() As List(Of AttackLog)
            Try
                RunningAttacks = JsonConvert.DeserializeObject(Of List(Of AttackLog))(Tools.getRequest($"https://safeguardauth.us/GetOnGoingAttacks?programid={ProgramInformation.ProgramId}&username={ResponseInformation.loginresponse.UserName}"))
            Catch
                RunningAttacks = New List(Of AttackLog)()
            End Try

            Return RunningAttacks
        End Function

        Function GetAmountOfAttacks(ByVal num As Integer) As List(Of AttackLog)
            Try
                PastAttacks = JsonConvert.DeserializeObject(Of List(Of AttackLog))(Tools.getRequest($"https://safeguardauth.us/GetPassedAttacks?programid={ProgramInformation.ProgramId}&username={ResponseInformation.loginresponse.UserName}&num={num}"))
            Catch
                PastAttacks = New List(Of AttackLog)()
            End Try

            Return PastAttacks
        End Function

        Function GetMethodInformation() As List(Of MethodStats)
            Try
                MethodInformation = JsonConvert.DeserializeObject(Of List(Of MethodStats))(Tools.getRequest($"https://safeguardauth.us/GetMethodStats?programid={ProgramInformation.ProgramId}&username={ResponseInformation.loginresponse.UserName}"))
            Catch
                MethodInformation = New List(Of MethodStats)()
            End Try

            Return MethodInformation
        End Function
    End Module

    Friend Module DiscordLogging
        Sub DiscordLog(ByVal action As String, ByVal username As String, ByVal ip As String, ByVal Optional geolocatedip As String = "")
            action = action.ToLower()
            Dim message As String
            Dim actionTitle As String
            Dim picture As String = "https://i.imgur.com/6leptM3.jpg"

            Select Case action
                Case "login"
                    message = $"{username} Has Just Logged In From {ip}!"
                    actionTitle = "Infinity Login"
                Case "geoip"
                    message = $"{username} Has Just GeoLocated this ip: {geolocatedip} from IP: {ip}!"
                    actionTitle = "Infinity GeoIP"
                Case "register"
                    message = $"{username} Has Registered!"
                    actionTitle = "Infinity Registrations"
                Case "attack"
                    message = $"{username} Has Just Sent An Attack to {ip}!"
                    actionTitle = "Infinity Attack"
                Case Else
                    message = $"{username} Has Done Unknown Function"
                    actionTitle = "Infinity Unknown"
            End Select

            LogToDiscord("", New DiscordHookObject() With {
                .Message = message,
                .Title = actionTitle,
                .Picture = picture,
                .ProgramId = ProgramInformation.ProgramId
            })
        End Sub

        Private Function LogToDiscord(ByVal apikey As String, ByVal DiscordObject As DiscordHookObject) As Boolean
            If DiscordObject Is Nothing Then Return False

            Try
                Tools.postRequest($"https://safeguardauth.us/LogToDiscordv2?apikey={apikey}", DiscordObject)
            Catch
                Return False
            End Try

            Return True
        End Function
    End Module

    Public Class DiscordHookObject
        Public Property Message As String
        Public Property Title As String
        Public Property Picture As String
        Public Property ProgramId As String
    End Class

    Friend Module Update
        Friend version As String = "1"

        Friend Sub update()
            ClientFunctions.AutoUpdate(version, ProgramInformation.ProgramId)
        End Sub
    End Module

    Friend Module ResponseInformation
        Friend Password As String
        Friend loginresponse As LoginResponse
        Friend registerinfo As RegisterInformationObject
        Friend count As Count
        Friend accountgen As AccountGen
    End Module

    Friend Module ProgramInformation
        Friend ProgramId As String = ""
    End Module

    Friend Module SafeGuardTitle
        Public safeguardtitle As String = "SafeGuardAuth.us"
    End Module

    Friend Class SafeCheck
        Friend Shared CurrentDllMD5 As String = "3307FC407D88BA40ABEAC87266F4558D"
        Friend Shared CurrentDllSHA1 As String = "3B85FC7EC65D4E26720516866E72B240598CEDCE"
        Friend Shared CurrentDllSHA256 As String = "B215110D42BDEC6069D1328E429C959F68C1BEE08333C4852BD3F5299B95173F"
        Friend Shared CurrentDllSize As String = "1741312"
        Friend Shared CurrentNewtonSoftMD5 As String = "F33CBE589B769956284868104686CC2D"
        Friend Shared CurrentNewtonSoftSHA1 As String = "2FB0BE100DE03680FC4309C9FA5A29E69397A980"
        Friend Shared CurrentNewtonSoftSHA256 As String = "973FD70CE48E5AC433A101B42871680C51E2FEBA2AEEC3D400DEA4115AF3A278"
        Friend Shared CurrentNewtonSoftSize As String = "653824"

        Friend Shared Sub Md5Check()
            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}SafeGuard.dll", "MD5") <> CurrentDllMD5 Then
                Console.WriteLine("Invalid SafeGuard.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}SafeGuard.dll", "SHA1") <> CurrentDllSHA1 Then
                Console.WriteLine("Invalid SafeGuard.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}SafeGuard.dll", "SHA256") <> CurrentDllSHA256 Then
                Console.WriteLine("Invalid SafeGuard.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}SafeGuard.dll", "SIZE") <> CurrentDllSize Then
                Console.WriteLine("Invalid SafeGuard.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}Newtonsoft.Json.dll", "MD5") <> CurrentNewtonSoftMD5 Then
                Console.WriteLine("Invalid Newtonsoft.Json.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}Newtonsoft.Json.dll", "SHA1") <> CurrentNewtonSoftSHA1 Then
                Console.WriteLine("Invalid Newtonsoft.Json.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}Newtonsoft.Json.dll", "SHA256") <> CurrentNewtonSoftSHA256 Then
                Console.WriteLine("Invalid Newtonsoft.Json.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If

            If ComputeHash($"{AppDomain.CurrentDomain.BaseDirectory}Newtonsoft.Json.dll", "SIZE") <> CurrentNewtonSoftSize Then
                Console.WriteLine("Invalid Newtonsoft.Json.dll. Exiting Program.", SafeGuardTitle.safeguardtitle)
                Environment.[Exit](2134)
            End If
        End Sub

        Friend Shared Function ComputeHash(ByVal s As String, ByVal hashtype As String) As String
            Select Case hashtype
                Case "MD5"

                    Using md5 As MD5 = MD5.Create()

                        Try

                            Using stream = File.OpenRead(s)
                                Dim hash As Byte() = md5.ComputeHash(stream)
                                Dim sb As StringBuilder = New StringBuilder()

                                For i As Integer = 0 To hash.Length - 1
                                    sb.Append(hash(i).ToString("X2"))
                                Next

                                Return sb.ToString()
                            End Using

                        Catch
                            Return "MD5 Error"
                        End Try
                    End Using

                Case "SHA1"

                    Using sha1 As SHA1 = SHA1.Create()

                        Try

                            Using stream = File.OpenRead(s)
                                Dim hash As Byte() = sha1.ComputeHash(stream)
                                Dim sb As StringBuilder = New StringBuilder()

                                For i As Integer = 0 To hash.Length - 1
                                    sb.Append(hash(i).ToString("X2"))
                                Next

                                Return sb.ToString()
                            End Using

                        Catch
                            Return "SHA1 Error"
                        End Try
                    End Using

                Case "SHA256"

                    Using sha256 As SHA256 = SHA256.Create()

                        Try

                            Using stream = File.OpenRead(s)
                                Dim hash As Byte() = sha256.ComputeHash(stream)
                                Dim sb As StringBuilder = New StringBuilder()

                                For i As Integer = 0 To hash.Length - 1
                                    sb.Append(hash(i).ToString("X2"))
                                Next

                                Return sb.ToString()
                            End Using

                        Catch
                            Return "SHA256 Error"
                        End Try
                    End Using

                Case "SIZE"

                    Try

                        Using stream = File.OpenRead(s)
                            Dim length As Long = New System.IO.FileInfo(s).Length
                            Return length.ToString()
                        End Using

                    Catch
                        Return "File Size Error"
                    End Try

                Case Else
                    Return "Invalid Type"
            End Select
        End Function
    End Class
End Namespace
