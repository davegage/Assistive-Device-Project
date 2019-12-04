Imports System.Data.OleDb
Imports System.Security.Cryptography
Public Class MenuSystemSecurity
    Dim mf As MenuSystemClass.MenuSystem_Functions
    Dim myMNU2GenConnection As OleDbConnection = New OleDbConnection
    Dim my97mastGenConnection As OleDbConnection = New OleDbConnection
    Dim mnuConstring As String = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=W:\menusystem\mnu2gen\mnu2gen.accdb"
    Dim _97constring As String = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=W:\menusystem\97mast.mdb"
    Public Sub New()
        my97mastGenConnection.ConnectionString = _97constring
        myMNU2GenConnection.ConnectionString = mnuConstring
        mf = New MenuSystemClass.MenuSystem_Functions
    End Sub
    Private Shared Function EncriptString(str As String)
        Dim bytes As Byte() = System.Text.Encoding.ASCII.GetBytes(str)
        Dim hashed = System.Security.Cryptography.SHA512.Create().ComputeHash(bytes)
        Return Convert.ToBase64String(hashed)
    End Function

    'Salt
    Public Shared Function GenerateSalt() As String
        Using cryotiServiceProvider As New System.Security.Cryptography.RNGCryptoServiceProvider
            Dim sb As New Text.StringBuilder
            Dim data As Byte() = New Byte(4) {}
            For i = 0 To 6
                cryotiServiceProvider.GetBytes(data)
                Dim value As String = BitConverter.ToString(data, 0)
                sb.Append(value)
            Next
            Return EncriptString(sb.ToString)

        End Using
    End Function
    Private Function returnSalt(Optional employeeID As Integer = Nothing)
        If employeeID = 0 Then
            employeeID = MenuSystemClass.returnID
        End If
        Dim salt As String = mf.returnScalar("SELECT [Salt] FROM [Rybak Employees] WHERE [Rybak ID] = " & employeeID, 1, myMNU2GenConnection)
        Return salt
    End Function
    Private Sub checkForSalt(Optional employeeID As Integer = Nothing)
        If employeeID = 0 Then
            employeeID = MenuSystemClass.returnID
        End If
        Dim salt As String = returnSalt(employeeID)
        If salt = "" Then
            mf.executeUpdateCMD("UPDATE [Rybak Employees] SET [Salt] = '" & GenerateSalt() & "' WHERE [Rybak ID] =" & employeeID, myMNU2GenConnection)
        End If
    End Sub




    'Password
    Private Function encryptPassword(password As String, employeeID As Integer)
        Dim passwordSTR As String = password
        For i = 0 To employeeID
            passwordSTR = (EncriptString(EncriptString(passwordSTR) & returnSalt(employeeID)))
        Next
        Return passwordSTR
    End Function

    Public Sub newPassword(password As String, hint As String, Optional requirePasswordChange As Boolean = False, Optional employeeID As Integer = Nothing)

        If employeeID = 0 Then
            employeeID = MenuSystemClass.returnID
        End If
        checkForSalt(employeeID)
        Dim encriptSaltPass As String = encryptPassword(password, employeeID)
        Dim encoder As New valueEncrypt("hint")
        Dim hintString As String = encoder.EncryptData(hint)
        mf.executeUpdateCMD("UPDATE [Rybak Employees] SET [MenuSystemPass] = '" & encriptSaltPass & "', [Hint] = '" & hintString & "', [Require Change] = " & requirePasswordChange & " WHERE [Rybak ID] =" & employeeID, myMNU2GenConnection)
    End Sub
    Public Function returnHint()
        Dim hint As String = mf.returnScalar("SELECT [Hint] FROM [Rybak Employees] WHERE [Rybak ID] = " & MenuSystemClass.returnID(), 1, myMNU2GenConnection)
        Dim decoder As New valueEncrypt("hint")
        Dim hintString As String = decoder.DecryptData(hint)
        Return hintString
    End Function
    Public Function checkForPasswordMatch(password As String, Optional employeeID As Integer = Nothing)
        If employeeID = 0 Then
            employeeID = MenuSystemClass.returnID
        End If
        Dim passMatch As Boolean = False
        Dim DBpass As String = mf.returnScalar("SELECT [MenuSystemPass] FROM [Rybak Employees] WHERE [Rybak ID] = " & employeeID, 1, myMNU2GenConnection)
        If DBpass = encryptPassword(password, employeeID) Then
            passMatch = True
        End If
        Return passMatch
    End Function


    Private Function checkForPassword()
        Dim passBool As Boolean
        Dim rybakID As Integer = MenuSystemClass.returnID()
        Dim password As String = mf.returnScalar("SELECT [MenuSystemPass] FROM [Rybak Employees] WHERE [Rybak ID] = " & rybakID, 1, myMNU2GenConnection)
        If password = "" Then
            passBool = False
        Else
            passBool = True
        End If
        Return passBool
    End Function
    Public Function checkForPasswordChange()
        Dim rybakID As Integer = MenuSystemClass.returnID()
        Dim passChange As Boolean = mf.returnScalar("SELECT [Require Change] FROM [Rybak Employees] WHERE [Rybak ID] = " & rybakID, 4, myMNU2GenConnection)
        Return passChange
    End Function
    Dim allowPass As Boolean = False
    Public Function passwordProtect()
        'Retrun 1 = Allow Entrance
        'Return 2 = Denied

        checkForSalt()
        Dim passBool As Boolean = checkForPassword()
        If passBool = False Then
            MessageBox.Show("Error: Your Account has been locked." & vbCrLf & "Please Contact your System Administrator.", "Error:", MessageBoxButtons.OK, MessageBoxIcon.Stop)
            Return False
        ElseIf passBool = True Then
            Return launchLogInForm()
        End If


    End Function

    Dim logInFormOBJ As logInForm

    Private Function launchLogInForm()
        logInFormOBJ = New logInForm
        AddHandler logInFormOBJ.FormClosing, AddressOf getLoginReturnVal
        logInFormOBJ.ShowDialog()
        Dim checkForPassChange As Boolean = checkForPasswordChange()
        If allowPass = True Then
            If checkForPasswordChange() = True Then
                launchChangePassword(1)
            End If
        End If
        Return allowPass
    End Function
    Private Sub getLoginReturnVal()
        allowPass = logInFormOBJ.passMatch
    End Sub
    Public Function launchChangePassword(mode As Integer, Optional employeeID As Integer = Nothing)
        Dim obj As New changePasswordFrom
        If employeeID <> 0 Then
            obj.employeeID = employeeID
        End If
        obj.mode = mode
        obj.ShowDialog()
    End Function




End Class
