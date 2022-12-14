using System;
using System.Collections.Generic;
using Firebase;
using Firebase.Auth;
using Firebase.Extensions;
using Google;
using UnityEngine;

namespace RGN.Modules.SignIn
{
    public class GoogleSignInModule : BaseModule<GoogleSignInModule>, IRGNModule
    {
        private IRGNRolesCore rgnCore;

        public GoogleSignInModule()
        {
        }

        public void SetRGNCore(IRGNRolesCore rgnCore)
        {
            this.rgnCore = rgnCore;
        }

        public void Init()
        {
            GoogleSignIn.Configuration = new GoogleSignInConfiguration {
                WebClientId = rgnCore.Dependencies.ApplicationStore.GetGoogleSignInWebClientID,
                UseGameSignIn = false,
                RequestEmail = true,
                RequestIdToken = true
            };
        }
        public void Dispose() { }

        public void SignOutFromGoogle()
        {
            OnSignOutGoogle();
            rgnCore.SignOutRGN();
        }

        public void OnSignInGoogle(bool isLink = false)
        {
            Debug.Log($"[GoogleSignInModule]: GOOGLE, login started");

            GoogleSignIn.DefaultInstance.SignIn().ContinueWithOnMainThread(task => {
                if (task.IsCanceled)
                {
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    using (IEnumerator<Exception> enumerator = task.Exception.InnerExceptions.GetEnumerator())
                    {
                        while (enumerator.MoveNext())
                        {
                            var error = (GoogleSignIn.SignInException)enumerator.Current;
                            Debug.Log("[GoogleSignInModule]: GOOGLE, login ERROR " + error.Status + " " +
                                      error.Message);
                        }
                    }

                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log($"[GoogleSignInModule]: GOOGLE, login SUCCESS {task.Result.DisplayName}||{task.Result.Email}||{task.Result.IdToken}");

                if (isLink)
                {
                    rgnCore.IsUserCanBeLinkedAsync(task.Result.Email).ContinueWithOnMainThread(checkLinkResult => {
                        if (checkLinkResult.IsCanceled)
                        {
                            SignOutFromGoogle();
                            return;
                        }

                        if (checkLinkResult.IsFaulted)
                        {
                            Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, checkLinkResult.Exception);
                            rgnCore.SignOutRGN();
                            rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                            return;
                        }

                        bool canBeLinked = (bool)checkLinkResult.Result.Data;
                        if (!canBeLinked)
                        {
                            OnSignOutGoogle();
                            rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                            return;
                        }

                        LinkGoogleAccountToFirebase(task.Result.IdToken);
                    });
                }
                else
                {
                    SignInWithGoogleOnFirebase(task.Result.IdToken);
                }
            });
        }

        private void LinkGoogleAccountToFirebase(string idToken)
        {
            var credential = rgnCore.ReadyMasterAuth.googleAuthProvider.GetCredential(idToken, null);

            rgnCore.Auth.CurrentUser.LinkAndRetrieveDataWithCredentialAsync(credential).ContinueWithOnMainThread(task => {
                if (task.IsCanceled)
                {
                    OnSignOutGoogle();
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    FirebaseAccountLinkException firebaseAccountLinkException = task.Exception.InnerException as FirebaseAccountLinkException;
                    if (firebaseAccountLinkException != null && firebaseAccountLinkException.ErrorCode == (int)AuthError.CredentialAlreadyInUse)
                    {
                        OnSignOutGoogle();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    FirebaseException firebaseException = task.Exception.InnerException as FirebaseException;
                    if (firebaseException != null && firebaseException.ErrorCode == (int)AuthError.EmailAlreadyInUse)
                    {
                        OnSignOutGoogle();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    foreach (Exception exception in task.Exception.Flatten().InnerExceptions)
                    {
                        Debug.Log(exception.GetType() + " - " + exception.Message + " - " + exception.Source);
                    }

                    OnSignOutGoogle();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log("[GoogleSignInModule]: LinkWith Google Successful. " + rgnCore.Auth.CurrentUser.UserId + " ");

                rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(taskAuth => {
                    if (taskAuth.IsCanceled)
                    {
                        SignOutFromGoogle();
                        return;
                    }
                    if (taskAuth.IsFaulted)
                    {
                        Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, taskAuth.Exception);
                        rgnCore.SignOutRGN();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    Debug.Log("[GoogleSignInModule]: GOOGLE, userToken " + taskAuth.Result);

                    rgnCore.LinkWithProviderAsync(false, taskAuth.Result).ContinueWithOnMainThread(taskLink => {
                        Debug.Log("[GoogleSignInModule]: GOOGLE, linked");

                        rgnCore.SetAuthCompletion(EnumLoginState.Success, EnumLoginError.Ok);
                    });
                });
            });
        }

        private void SignInWithGoogleOnFirebase(string idToken)
        {
            var credential = rgnCore.ReadyMasterAuth.googleAuthProvider.GetCredential(idToken, null);

            rgnCore.Auth.SignInWithCredentialAsync(credential).ContinueWithOnMainThread(task => {
                if (task.IsCanceled)
                {
                    SignOutFromGoogle();
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    SignOutFromGoogle();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log("[GoogleSignInModule]: GOOGLE, signed in");

                rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(taskAuth => {
                    Debug.Log("[GoogleSignInModule]: GOOGLE, userToken " + taskAuth.Result);

                    rgnCore.CreateCustomTokenAsync(taskAuth.Result).ContinueWith(taskCustom => {
                        Debug.Log("[GoogleSignInModule]: GOOGLE, masterToken " + taskCustom.Result);

                        rgnCore.ReadyMasterAuth.SignInWithCustomTokenAsync(taskCustom.Result);
                    });
                });
            });
        }

        private static void OnSignOutGoogle()
        {
            GoogleSignIn.DefaultInstance.SignOut();
        }
    }
}
